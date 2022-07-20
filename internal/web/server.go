package web

import (
	"fmt"
	"github.com/gorilla/websocket"
	"go-certstream-server/internal/certstream"
	"log"
	"net/http"
	"time"
)

var ClientHandler = BroadcastManager{}
var exampleCert certstream.Entry
var upgrader = websocket.Upgrader{} // use default options

// initWebsocket is called when a client connects to the websocket endpoint.
// It upgrades the connection to a websocket and starts a goroutine to listen for messages from the client.
func initWebsocket(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	log.Printf("Starting new websocket for '%s'\n", r.RemoteAddr)
	connection, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error while trying to upgrade connection:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	connection.EnableWriteCompression(true)
	// TODO connection.SetCompressionLevel(flate.BestCompression)
	connection.SetCloseHandler(func(code int, text string) error {
		log.Printf("Stopping websocket for '%s'\n", r.RemoteAddr)
		message := websocket.FormatCloseMessage(code, "Connection closed")
		return connection.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second))
	})
	client := &client{
		conn:          connection,
		broadcastChan: make(chan []byte, 100),
		fullStream:    r.URL.Path == "/full-stream",
		name:          r.RemoteAddr,
	}
	go client.broadcastHandler()
	go client.listenWebsocket()

	ClientHandler.registerClient(client)
}

func example(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(exampleCert.JSONLite()) //nolint:errcheck
}

func exampleFull(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(exampleCert.JSON()) //nolint:errcheck
}

func SetExampleCert(cert certstream.Entry) {
	exampleCert = cert
}

// StartServer initializes the webserver and starts listening for connections.
func StartServer(networkIf string, port int) {
	var addr = fmt.Sprintf("%s:%d", networkIf, port)
	log.Printf("Starting webserver on %s\n", addr)

	http.HandleFunc("/", initWebsocket)
	http.HandleFunc("/full-stream", initWebsocket)
	http.HandleFunc("/example.json", example)
	http.HandleFunc("/full-example.json", exampleFull)

	ClientHandler.Broadcast = make(chan certstream.Entry, 10_000)
	go ClientHandler.broadcaster()

	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
