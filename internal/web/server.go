package web

import (
	"crypto/tls"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gorilla/websocket"
	"go-certstream-server/internal/certstream"
	"go-certstream-server/internal/config"
	"io"
	"log"
	"net/http"
	"time"
)

var ClientHandler = BroadcastManager{}
var upgrader = websocket.Upgrader{} // use default options

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
		callback(w, false)
	})
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
	c := &client{
		conn:          connection,
		broadcastChan: make(chan []byte, 100),
		name:          name,
		subType:       subscriptionType,
	}
	go c.broadcastHandler()
	go c.listenWebsocket()

	ClientHandler.registerClient(c)
}

// setupWebsocketRoutes configures all the routes necessary for the websocket webserver
func setupWebsocketRoutes() *chi.Mux {
	r := chi.NewRouter()
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
	return r
}

func (ws *WebServer) initServer() {
	var addr = fmt.Sprintf("%s:%d", ws.networkIf, ws.port)

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

// NewMetricsServer creates a new webserver that listens on the given port and provides metrics for a prometheus server.
func NewMetricsServer(networkIf string, port int, certPath, keyPath string) *WebServer {
	server := &WebServer{
		networkIf: networkIf,
		port:      port,
		routes:    chi.NewRouter(),
		certPath:  certPath,
		keyPath:   keyPath,
	}
	server.initServer()
	server.routes.Use(middleware.Recoverer)
	return server
}

// NewWebsocketServer starts a new webserver and initialized it with the necessary routes.
// It also starts the broadcaster in ClientHandler as a background job.
func NewWebsocketServer(networkIf string, port int, certPath, keyPath string) *WebServer {
	server := &WebServer{
		networkIf: networkIf,
		port:      port,
		routes:    setupWebsocketRoutes(),
		certPath:  certPath,
		keyPath:   keyPath,
	}
	server.initServer()
	ClientHandler.Broadcast = make(chan certstream.Entry, 10_000)
	go ClientHandler.broadcaster()
	return server
}

// Start initializes the webserver and starts listening for connections.
func (ws *WebServer) Start() {
	var addr = fmt.Sprintf("%s:%d", ws.networkIf, ws.port)
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
