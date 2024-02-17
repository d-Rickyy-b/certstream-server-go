package web

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certstream"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"

	"github.com/gorilla/websocket"
)

var (
	ClientHandler = BroadcastManager{}
	upgrader      = websocket.Upgrader{} // use default options
)

type WebServer struct {
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
func (ws *WebServer) RegisterPrometheus(url string, callback func(w io.Writer, exposeProcessMetrics bool)) {
	ws.routes.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
		callback(w, config.AppConfig.Prometheus.ExposeSystemMetrics)
	})
}

// IPWhitelist returns a middleware that checks if the IP of the client is in the whitelist.
func IPWhitelist(whitelist []string) func(next http.Handler) http.Handler {
	// build a list of whitelisted IPs and CIDRs
	log.Println("Building IP whitelist...")
	var ipList []net.IP
	var cidrList []net.IPNet

	for _, element := range whitelist {
		ip, ipNet, err := net.ParseCIDR(element)
		if err != nil {
			if ip = net.ParseIP(element); ip == nil {
				log.Println("Invalid IP in metrics whitelist: ", element)
				continue
			}

			ipList = append(ipList, ip)
			continue
		}

		cidrList = append(cidrList, *ipNet)
	}

	log.Println("IP whitelist: ", ipList)
	log.Println("CIDR whitelist: ", cidrList)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// if the whitelist is empty, just continue
			if len(ipList) == 0 && len(cidrList) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ipString, _, err := net.SplitHostPort(r.RemoteAddr)
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

			log.Printf("IP %s not in whitelist, rejecting request\n", r.RemoteAddr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		})
	}
}

// initFullWebsocket is called when a client connects to the /full-stream endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initFullWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		log.Println("Error while trying to upgrade connection:", err)
		return
	}

	setupClient(connection, SubTypeFull, r.RemoteAddr)
}

// initLiteWebsocket is called when a client connects to the / endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initLiteWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		log.Println("Error while trying to upgrade connection:", err)
		return
	}

	setupClient(connection, SubTypeLite, r.RemoteAddr)
}

// initDomainWebsocket is called when a client connects to the /domains-only endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initDomainWebsocket(w http.ResponseWriter, r *http.Request) {
	connection, err := upgradeConnection(w, r)
	if err != nil {
		log.Println("Error while trying to upgrade connection:", err)
		return
	}

	setupClient(connection, SubTypeDomain, r.RemoteAddr)
}

// upgradeConnection upgrades the connection to a websocket and returns the connection.
func upgradeConnection(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	var remoteAddr string

	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		remoteAddr = fmt.Sprintf("'%s' (X-Forwarded-For: '%s')", r.RemoteAddr, xForwardedFor)
	} else {
		remoteAddr = fmt.Sprintf("'%s'", r.RemoteAddr)
	}

	log.Printf("Starting new websocket for %s - %s\n", remoteAddr, r.URL)

	connection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}

	defaultCloseHandler := connection.CloseHandler()
	connection.SetCloseHandler(func(code int, text string) error {
		log.Printf("Stopping websocket for %s - %s\n", remoteAddr, r.URL)
		return defaultCloseHandler(code, text)
	})

	return connection, nil
}

// setupClient initializes a client struct and starts the broadcastHandler and websocket listener.
func setupClient(connection *websocket.Conn, subscriptionType SubscriptionType, name string) {
	c := newClient(connection, subscriptionType, name, 300)
	go c.broadcastHandler()
	go c.listenWebsocket()

	ClientHandler.registerClient(c)
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

func (ws *WebServer) initServer() {
	addr := fmt.Sprintf("%s:%d", ws.networkIf, ws.port)

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256, tls.X25519},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	ws.server = &http.Server{
		Addr:              addr,
		Handler:           ws.routes,
		TLSConfig:         tlsConfig,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
}

// NewMetricsServer creates a new webserver that listens on the given port and provides metrics for a metrics server.
func NewMetricsServer(networkIf string, port int, certPath, keyPath string) *WebServer {
	server := &WebServer{
		networkIf: networkIf,
		port:      port,
		routes:    chi.NewRouter(),
		certPath:  certPath,
		keyPath:   keyPath,
	}
	server.routes.Use(middleware.Recoverer)

	if config.AppConfig.Prometheus.RealIP {
		server.routes.Use(middleware.RealIP)
	}

	// Enable IP whitelist if configured
	if len(config.AppConfig.Prometheus.Whitelist) > 0 {
		server.routes.Use(IPWhitelist(config.AppConfig.Prometheus.Whitelist))
	}

	server.initServer()

	return server
}

// NewWebsocketServer starts a new webserver and initialized it with the necessary routes.
// It also starts the broadcaster in ClientHandler as a background job.
func NewWebsocketServer(networkIf string, port int, certPath, keyPath string) *WebServer {
	server := &WebServer{
		networkIf: networkIf,
		port:      port,
		routes:    chi.NewRouter(),
		certPath:  certPath,
		keyPath:   keyPath,
	}

	if config.AppConfig.Webserver.RealIP {
		server.routes.Use(middleware.RealIP)
	}

	// Enable IP whitelist if configured
	if len(config.AppConfig.Webserver.Whitelist) > 0 {
		server.routes.Use(IPWhitelist(config.AppConfig.Webserver.Whitelist))
	}

	setupWebsocketRoutes(server.routes)
	server.initServer()

	ClientHandler.Broadcast = make(chan certstream.Entry, 10_000)
	go ClientHandler.broadcaster()

	return server
}

// Start initializes the webserver and starts listening for connections.
func (ws *WebServer) Start() {
	addr := fmt.Sprintf("%s:%d", ws.networkIf, ws.port)
	log.Printf("Starting webserver on %s\n", addr)

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
