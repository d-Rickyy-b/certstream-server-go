package web

import (
	"crypto/tls"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/gorilla/websocket"
	"go-certstream-server/internal/certstream"
	"go-certstream-server/internal/config"
	"log"
	"net/http"
	"time"
)

var ClientHandler = BroadcastManager{}
var exampleCert certstream.Entry
var upgrader = websocket.Upgrader{} // use default options

type WebsocketServer struct {
	Routes *chi.Mux
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
	log.Printf("Starting new websocket for '%s' - %s\n", r.RemoteAddr, r.URL)
	connection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}

	connection.SetCloseHandler(func(code int, text string) error {
		log.Printf("Stopping websocket for '%s' - %s\n", r.RemoteAddr, r.URL)
		message := websocket.FormatCloseMessage(code, "Connection closed")
		return connection.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second))
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

// exampleFull handles requests to the /full-stream/example.json endpoint.
// It returns a JSON representation of the full example certificate.
func exampleFull(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(exampleCert.JSON()) //nolint:errcheck
}

// exampleLite handles requests to the /example.json endpoint.
// It returns a JSON representation of the lite example certificate.
func exampleLite(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(exampleCert.JSONLite()) //nolint:errcheck
}

// exampleDomains handles requests to the /domains-only/example.json endpoint.
// It returns a JSON representation of the domain data.
func exampleDomains(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(exampleCert.JSONDomains()) //nolint:errcheck
}

func SetExampleCert(cert certstream.Entry) {
	exampleCert = cert
}

// setupRoutes configures all the routes necessary for the webserver
func setupRoutes() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Route("/", func(r chi.Router) {
		r.Route(config.AppConfig.Webserver.FullURL, func(r chi.Router) {
			r.HandleFunc("/", initFullWebsocket)
			r.HandleFunc("/example", exampleFull)
		})

		r.Route(config.AppConfig.Webserver.LiteURL, func(r chi.Router) {
			r.HandleFunc("/", initLiteWebsocket)
			r.HandleFunc("/example", exampleLite)
		})

		r.Route(config.AppConfig.Webserver.DomainsOnlyURL, func(r chi.Router) {
			r.HandleFunc("/", initDomainWebsocket)
			r.HandleFunc("/example", exampleDomains)
		})
	})
	return r
}

// StartServer initializes the webserver and starts listening for connections.
func StartServer(networkIf string, port int) {
	var addr = fmt.Sprintf("%s:%d", networkIf, port)
	log.Printf("Starting webserver on %s\n", addr)

	r := setupRoutes()

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256, tls.X25519},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	ClientHandler.Broadcast = make(chan certstream.Entry, 10_000)
	go ClientHandler.broadcaster()

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           r,
		TLSConfig:         tlsConfig,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	err := httpServer.ListenAndServe()
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
