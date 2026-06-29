package web

import (
	"fmt"
	"log/slog"
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
	writeWait := 60 * time.Second
	pingTicker := time.NewTicker(30 * time.Second)

	defer func() {
		slog.Info("Closing broadcast handler for client", "remote_addr", c.conn.RemoteAddr())

		pingTicker.Stop()

		_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
		_ = c.conn.Close()
	}()

	for {
		select {
		case <-pingTicker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))

			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case message := <-c.broadcastChan:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				slog.Error("Error while getting next writer", "error", err)
				return
			}

			_, writeErr := w.Write(message)
			if writeErr != nil {
				slog.Error("Error while writing", "error", writeErr)
			}

			if closeErr := w.Close(); closeErr != nil {
				slog.Error("Error while closing writer", "error", closeErr)
				return
			}
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

	readWait := 65 * time.Second

	c.conn.SetReadLimit(512)
	_ = c.conn.SetReadDeadline(time.Now().Add(readWait))

	defaultPingHandler := c.conn.PingHandler()

	c.conn.SetPingHandler(func(appData string) error {
		// Ping received - reset the deadline
		err := c.conn.SetReadDeadline(time.Now().Add(readWait))
		if err != nil {
			return fmt.Errorf("error while setting read deadline: %w", err)
		}

		return defaultPingHandler(appData)
	})

	c.conn.SetPongHandler(func(string) error {
		// Pong received - reset the deadline
		err := c.conn.SetReadDeadline(time.Now().Add(readWait))
		if err != nil {
			return fmt.Errorf("error while setting read deadline: %w", err)
		}

		return nil
	})

	// Handle messages from the client
	for {
		// ignore any message sent from clients - we only handle errors (aka. disconnects)
		_, _, readErr := c.conn.ReadMessage()
		if readErr != nil {
			if websocket.IsUnexpectedCloseError(readErr, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Warn("Unexpected websocket close error", "error", readErr)
			}

			// If client fails to send ping messages
			if strings.Contains(strings.ToLower(readErr.Error()), "i/o timeout") {
				slog.Warn("No ping received from client", "remote_addr", c.conn.RemoteAddr())

				closeMessage := websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "No ping received!")

				writeErr := c.conn.WriteControl(websocket.CloseMessage, closeMessage, time.Now().Add(5*time.Second))
				if writeErr != nil {
					slog.Error("Error while sending close message", "error", writeErr)
				}
			} else if strings.Contains(strings.ToLower(readErr.Error()), "an existing connection was forcibly closed by the remote host") {
				slog.Info("Connection to client lost", "remote_addr", c.conn.RemoteAddr())
			}

			slog.Info("Disconnecting client", "remote_addr", c.conn.RemoteAddr())

			break
		}
	}
}
