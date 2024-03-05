package web

import (
	"log"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	SubTypeFull SubscriptionType = iota
	SubTypeLite
	SubTypeDomain
)

type SubscriptionType int

// client represents a single client's connection to the server.
type client struct {
	conn          *websocket.Conn
	broadcastChan chan []byte
	name          string
	subType       SubscriptionType
	skippedCerts  uint64
}

func newClient(conn *websocket.Conn, subType SubscriptionType, name string, certBufferSize int) *client {
	return &client{
		conn:          conn,
		broadcastChan: make(chan []byte, certBufferSize),
		name:          name,
		subType:       subType,
	}
}

// Each client has a broadcastHandler that runs in the background and sends out the broadcast messages to the client.
func (c *client) broadcastHandler() {
	defer func() {
		log.Println("Closing broadcast handler for client:", c.conn.RemoteAddr())
		_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
		_ = c.conn.Close()
	}()

	for message := range c.broadcastChan {
		_ = c.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))

		w, err := c.conn.NextWriter(websocket.TextMessage)
		if err != nil {
			log.Printf("Error while getting next writer: %v\n", err)
			return
		}

		_, writeErr := w.Write(message)
		if writeErr != nil {
			log.Printf("Error while writing: %v\n", writeErr)
		}

		if closeErr := w.Close(); closeErr != nil {
			log.Printf("Error while closing: %v\n", closeErr)
			return
		}
	}
}

// listenWebsocket is running in the background on a goroutine and listens for messages from the client.
// It responds to ping messages with a pong message. It closes the connection if the client sends
// a close message or no ping is received within 65 seconds.
func (c *client) listenWebsocket() {
	defer func() {
		_ = c.conn.Close()
		ClientHandler.unregisterClient(c)
	}()

	c.conn.SetReadLimit(512)
	_ = c.conn.SetReadDeadline(time.Now().Add(65 * time.Second))

	defaultPingHandler := c.conn.PingHandler()
	c.conn.SetPingHandler(func(appData string) error {
		// Ping received - reset the ping deadline to 65 seconds
		_ = c.conn.SetReadDeadline(time.Now().Add(65 * time.Second))
		return defaultPingHandler(appData)
	})
	c.conn.SetPongHandler(func(string) error {
		// Pong received
		return nil
	})

	// Handle messages from the client
	for {
		// ignore any message sent from clients - we only handle errors (aka. disconnects)
		_, _, readErr := c.conn.ReadMessage()
		if readErr != nil {
			if websocket.IsUnexpectedCloseError(readErr, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Unexpected websocket close error: %v\n", readErr)
			}

			if strings.Contains(strings.ToLower(readErr.Error()), "i/o timeout") {
				log.Printf("No ping received from client: %v\n", c.conn.RemoteAddr())
				closeMessage := websocket.FormatCloseMessage(websocket.CloseNoStatusReceived, "No ping received!")
				c.conn.WriteControl(websocket.CloseMessage, closeMessage, time.Now().Add(5*time.Second)) //nolint:errcheck
			} else if strings.Contains(strings.ToLower(readErr.Error()), "an existing connection was forcibly closed by the remote host") {
				log.Printf("Connection to client lost: %v\n", c.conn.RemoteAddr())
			}

			log.Printf("Disconnecting client %v!\n", c.conn.RemoteAddr())

			break
		}
	}
}
