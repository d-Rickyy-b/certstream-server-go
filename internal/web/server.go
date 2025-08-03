package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/broadcast"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/websocket"
)

var (
	ClientHandler = NewBroadcastManager()
	upgrader      websocket.Upgrader
)

type contextKey int

const (
	// origConnAddrKey is the context key under which the original TCP connection
	// address (r.RemoteAddr before any RealIP rewriting) is stored.
	origConnAddrKey contextKey = iota
)

// Server is a struct that holds the necessary information to run a webserver.
// It is used for the websocket server as well as the metrics server.
type Server struct {
	networkIf string
	port      int
	routes    *chi.Mux
	server    *http.Server
	certPath  string
	keyPath   string
}

// RegisterPrometheus registers a new handler that listens on the given url and calls the given function
// in order to provide metrics for a prometheus server. This function signature was used, because VictoriaMetrics
// offers exactly this function signature.
func (ws *Server) RegisterPrometheus(url string, callback func(w io.Writer, exposeProcessMetrics bool)) {
	ws.routes.HandleFunc(url, func(w http.ResponseWriter, _ *http.Request) {
		callback(w, config.AppConfig.Prometheus.ExposeSystemMetrics)
	})
}

// getForwardedIP extracts the real client IP from well-known reverse-proxy headers.
// Order of precedence: X-Forwarded-For > X-Real-IP.
// Returns an empty string when no valid IP is found in any header.
func getForwardedIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			if parsed := net.ParseIP(ip); parsed != nil {
				return parsed.String()
			}
		}
	}

	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			return parsed.String()
		}
	}

	return ""
}

// realIPMiddleware returns a middleware that always stores the original r.RemoteAddr
// in the request context (under origConnAddrKey) before anything can overwrite it.
//
// When realIP is true it also rewrites r.RemoteAddr to the forwarded client IP taken
// from proxy headers (X-Forwarded-For / X-Real-IP).
//
// If trustedProxies is non-empty the rewrite is only performed when the actual TCP
// connection IP is in that list; otherwise a warning is logged and r.RemoteAddr is
// left unchanged. An empty trustedProxies list means every connecting IP is trusted,
// which preserves the previous behavior.
func realIPMiddleware(realIP bool, trustedProxies []string) func(next http.Handler) http.Handler {
	ipList, cidrList := generateIPList(trustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always capture the real TCP connection address before anything overwrites it.
			origAddr := r.RemoteAddr
			ctx := context.WithValue(r.Context(), origConnAddrKey, origAddr)
			r = r.WithContext(ctx)

			// If extracting the realIP is not desired, skip the rest of the middleware.
			if !realIP {
				next.ServeHTTP(w, r)
				return
			}

			// Parse the actual connection IP to check if the relevant headers can be trusted.
			connIPStr, _, err := net.SplitHostPort(origAddr)
			if err != nil {
				connIPStr = origAddr
			}

			connIP := net.ParseIP(connIPStr)

			// Empty trusted_proxies = trust every connection.
			trusted := len(ipList) == 0 && len(cidrList) == 0

			// If trusted_proxies is not empty, check if connIP is contained within trusted_proxies.
			if !trusted && connIP != nil {
				for _, cidr := range cidrList {
					if cidr.Contains(connIP) {
						trusted = true
						break
					}
				}

				if !trusted {
					for _, trustedIP := range ipList {
						if trustedIP.Equal(connIP) {
							trusted = true
							break
						}
					}
				}
			}

			// If the source IP is trusted, replace the RemoteAddr with the IP from the header.
			if trusted {
				if fwdIP := getForwardedIP(r); fwdIP != "" {
					r.RemoteAddr = fwdIP
				}
			} else {
				log.Printf("Warning: connection from %s is not in trusted_proxies, ignoring forwarded IP headers\n", origAddr) //nolint:gosec
			}

			next.ServeHTTP(w, r)
		})
	}
}

// IPWhitelist returns a middleware that checks if the IP of the client is in the whitelist.
// It always checks against the original TCP connection IP (stored in context by
// newRealIPMiddleware), so the whitelist cannot be bypassed via forwarded headers.
func IPWhitelist(whitelist []string) func(next http.Handler) http.Handler {
	ipList, cidrList := generateIPList(whitelist)

	log.Println("IP whitelist: ", ipList)
	log.Println("CIDR whitelist: ", cidrList)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// if the whitelist is empty, just continue
			if len(ipList) == 0 && len(cidrList) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Use the original TCP connection IP stored in context so that the
			// whitelist check is not affected by forwarded-for headers.
			addrToCheck := r.RemoteAddr
			if origAddr, ok := r.Context().Value(origConnAddrKey).(string); ok && origAddr != "" {
				addrToCheck = origAddr
			}

			ipString, _, err := net.SplitHostPort(addrToCheck)
			if err != nil {
				http.Error(w, "InternalServerError", http.StatusInternalServerError)
				return
			}

			ip := net.ParseIP(ipString)

			for _, cidr := range cidrList {
				if cidr.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}

			for _, whitelistedIP := range ipList {
				if whitelistedIP.Equal(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}

			log.Printf("IP %s not in whitelist, rejecting request\n", addrToCheck) //nolint:gosec
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

// generateIPList parses and returns two slices of net.IP and net.IPNet from a string slice.
// The input string slice needs to contain IP addresses or CIDR notations. Invalid entries are ignored.
func generateIPList(inputIPList []string) ([]net.IP, []net.IPNet) {
	var ipList []net.IP
	var cidrList []net.IPNet

	for _, element := range inputIPList {
		_, ipNet, err := net.ParseCIDR(element)
		if err == nil {
			cidrList = append(cidrList, *ipNet)
			continue
		}

		if ip := net.ParseIP(element); ip != nil {
			ipList = append(ipList, ip)
		}
	}

	return ipList, cidrList
}

// initFullWebsocket is called when a client connects to the /full-stream endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initFullWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		log.Println("Error while trying to upgrade connection:", err)
		return
	}

	setupClient(connection, broadcast.SubTypeFull, r.RemoteAddr)
}

// initLiteWebsocket is called when a client connects to the / endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initLiteWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		log.Println("Error while trying to upgrade connection:", err)
		return
	}

	setupClient(connection, broadcast.SubTypeLite, r.RemoteAddr)
}

// initDomainWebsocket is called when a client connects to the /domains-only endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initDomainWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		log.Println("Error while trying to upgrade connection:", err)
		return
	}

	setupClient(connection, broadcast.SubTypeDomain, r.RemoteAddr)
}

// upgradeConnection upgrades the connection to a websocket and returns the connection.
func upgradeConnection(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	var remoteAddr string

	ipFromHeader, _ := r.Context().Value(origConnAddrKey).(string)
	if ipFromHeader != "" && ipFromHeader != r.RemoteAddr {
		remoteAddr = fmt.Sprintf("'%s' (via proxy '%s')", ipFromHeader, r.RemoteAddr)
	} else {
		remoteAddr = fmt.Sprintf("'%s'", r.RemoteAddr)
	}

	log.Printf("Starting new websocket for %s - URI: '%s'\n", remoteAddr, r.URL) //nolint:gosec

	connection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, fmt.Errorf("error while upgrading connection: %w", err)
	}

	defaultCloseHandler := connection.CloseHandler()
	connection.SetCloseHandler(func(code int, text string) error {
		log.Printf("Stopping websocket for %s - URI: '%s'\n", remoteAddr, r.URL) //nolint:gosec
		return defaultCloseHandler(code, text)
	})

	return connection, nil
}

// setupClient initializes a client struct and starts the broadcastHandler and websocket listener.
func setupClient(connection *websocket.Conn, subscriptionType broadcast.SubscriptionType, name string) {
	// Extract data from request
	origConnAddr, _ := r.Context().Value(origConnAddrKey).(string)

	hostIP, hostPort, err := net.SplitHostPort(origConnAddr)
	if err != nil {
		log.Printf("Error while trying to parse remote address: %s\n", origConnAddr) //nolint:gosec
	}

	// Only pass the real IP from header if the RemoteAddr was altered
	realIPFromHeader := ""
	if r.RemoteAddr != origConnAddr {
		realIPFromHeader = r.RemoteAddr
	}

	data := clientData{
		userAgent:        r.Header.Get("User-Agent"),
		connectionIP:     hostIP,
		connectionPort:   hostPort,
		realIPFromHeader: realIPFromHeader,
	}

	c := broadcast.NewWebsocketClient(connection, subscriptionType, name, config.AppConfig.General.BufferSizes.Websocket)
	broadcast.ClientHandler.RegisterClient(c)
}

// setupWebsocketRoutes configures all the routes necessary for the websocket webserver.
func setupWebsocketRoutes(r *chi.Mux) {
	r.Use(middleware.Recoverer)
	r.Route("/", func(r chi.Router) {
		r.Route(config.AppConfig.Webserver.FullURL, func(r chi.Router) {
			r.HandleFunc("/", initFullWebsocket)
			r.HandleFunc("/example.json", exampleFull)
		})

		r.Route(config.AppConfig.Webserver.LiteURL, func(r chi.Router) {
			r.HandleFunc("/", initLiteWebsocket)
			r.HandleFunc("/example.json", exampleLite)
		})

		r.Route(config.AppConfig.Webserver.DomainsOnlyURL, func(r chi.Router) {
			r.HandleFunc("/", initDomainWebsocket)
			r.HandleFunc("/example.json", exampleDomains)
		})
	})
}

func (ws *Server) initServer() {
	addr := net.JoinHostPort(ws.networkIf, strconv.Itoa(ws.port))

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256, tls.X25519},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	ws.server = &http.Server{
		Addr:              addr,
		Handler:           ws.routes,
		TLSConfig:         tlsConfig,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
}

// NewMetricsServer creates a new webserver that listens on the given port and provides metrics for a metrics server.
func NewMetricsServer(networkIf string, port int, certPath, keyPath string) *Server {
	metricsServer := &Server{
		networkIf: networkIf,
		port:      port,
		routes:    chi.NewRouter(),
		certPath:  certPath,
		keyPath:   keyPath,
	}
	metricsServer.routes.Use(middleware.Recoverer)
	metricsServer.routes.Use(realIPMiddleware(
		config.AppConfig.Prometheus.RealIP,
		config.AppConfig.Prometheus.TrustedProxies,
	))

	// Enable IP whitelist if configured
	if len(config.AppConfig.Prometheus.Whitelist) > 0 {
		metricsServer.routes.Use(IPWhitelist(config.AppConfig.Prometheus.Whitelist))
	}

	metricsServer.initServer()

	return metricsServer
}

// NewWebsocketServer starts a new webserver and initialized it with the necessary routes.
// It also takes care of setting up websocket.Upgrader.
func NewWebsocketServer(networkIf string, port int, certPath, keyPath string) *Server {
	websocketServer := &Server{
		networkIf: networkIf,
		port:      port,
		routes:    chi.NewRouter(),
		certPath:  certPath,
		keyPath:   keyPath,
	}

	upgrader = websocket.Upgrader{
		EnableCompression: config.AppConfig.Webserver.CompressionEnabled,
		CheckOrigin: func(_ *http.Request) bool {
			// Allow all connections by default
			return true
		},
	}

	websocketServer.routes.Use(realIPMiddleware(
		config.AppConfig.Webserver.RealIP,
		config.AppConfig.Webserver.TrustedProxies,
	))

	// Enable IP whitelist if configured
	if len(config.AppConfig.Webserver.Whitelist) > 0 {
		websocketServer.routes.Use(IPWhitelist(config.AppConfig.Webserver.Whitelist))
	}

	setupWebsocketRoutes(websocketServer.routes)
	websocketServer.initServer()

	return websocketServer
}

// Start initializes the webserver and starts listening for connections.
func (ws *Server) Start() {
	log.Printf("Starting webserver on %s\n", ws.server.Addr)

	var err error
	if ws.keyPath != "" && ws.certPath != "" {
		err = ws.server.ListenAndServeTLS(ws.certPath, ws.keyPath)
	} else {
		err = ws.server.ListenAndServe()
	}

	if err != nil {
		log.Fatal("Error while serving webserver: ", err)
	}
}

// Stop tries to stop the webserver gracefully. If it doesn't stop within 15 seconds, it is forcefully closed.
func (ws *Server) Stop() {
	log.Println("Stopping webserver...")

	if err := ws.shutdown(); err != nil {
		log.Fatal("Error while stopping webserver: ", err)
	}
}

// shutdown is called by Stop() and tries to stops the webserver gracefully.
// If it doesn't stop within 15 seconds, it is forcefully closed.
func (ws *Server) shutdown() error {
	// If the server did not stop within 15 seconds, forcefully close it
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := ws.server.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("error during server shutdown: %w", err)
	}

	return nil
}
