package web

import (
	"github.com/gorilla/websocket"
	"log"
	"time"
)

// client represents a single client's connection to the server.
type client struct {
	conn          *websocket.Conn
	broadcastChan chan []byte
	name          string
	fullStream    bool
}

// Each client has a broadcastHandler that runs in the background and sends out the broadcast messages to the client.
func (c *client) broadcastHandler() {
	for message := range c.broadcastChan {
		c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

		w, err := c.conn.NextWriter(websocket.TextMessage)
		if err != nil {
			return
		}
		w.Write(message) //nolint:errcheck
		if err := w.Close(); err != nil {
			return
		}
	}

	_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
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
	c.conn.SetReadDeadline(time.Now().Add(65 * time.Second)) //nolint:errcheck

	defaultPingHandler := c.conn.PingHandler()
	c.conn.SetPingHandler(func(appData string) error {
		// Ping received - reset the ping deadline of 65 seconds
		c.conn.SetReadDeadline(time.Now().Add(65 * time.Second)) //nolint:errcheck
		return defaultPingHandler(appData)
	})
	c.conn.SetPongHandler(func(string) error {
		// Pong received
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("error: %v", err)
			}
			log.Println("Disconnecting client!")
			break
		}
		// ignore any message sent from clients - we only handle errors (aka. disconnects)
		_ = message
	}
}
