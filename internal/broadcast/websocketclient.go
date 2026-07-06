package broadcast

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const idChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// WebsocketClient represents a single WebSocket client's connection to the server.
type WebsocketClient struct {
	conn             *websocket.Conn
	userAgent        string
	hostIP           string
	hostPort         string
	realIPFromHeader string

	*BaseClient
}

// NewWebsocketClient creates a new WebSocket client from the given connection.
func NewWebsocketClient(conn *websocket.Conn, subType SubscriptionType, name, userAgent, hostIP, hostPort, realIPFromHeader string, certBufferSize int) *WebsocketClient {
	c := &WebsocketClient{
		conn:             conn,
		userAgent:        userAgent,
		hostIP:           hostIP,
		hostPort:         hostPort,
		realIPFromHeader: realIPFromHeader,
		BaseClient: &BaseClient{
			broadcastChan: make(chan []byte, certBufferSize),
			name:          name,
			subType:       subType,
		},
	}
	go c.broadcastHandler()
	go c.listenWebsocket()

	return c
}

// generateClientID generates a random 8-char identifier for the client.
func generateClientID() string {
	clientID := make([]byte, 8)
	for i := range clientID {
		//nolint:gosec
		clientID[i] = idChars[rand.Intn(len(idChars))]
	}

	return string(clientID)
}

// Each client has a broadcastHandler that runs in the background and sends out the broadcast messages to the client.
func (c *WebsocketClient) broadcastHandler() {
	writeWait := 60 * time.Second
	pingTicker := time.NewTicker(30 * time.Second)

	defer func() {
		log.Println("Closing broadcast handler for client:", c.Name()) //nolint:gosec

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
}

// listenWebsocket is running in the background on a goroutine and listens for messages from the client.
// It responds to ping messages with a pong message. It closes the connection if the client sends
// a close message or no ping is received within 65 seconds.
func (c *WebsocketClient) listenWebsocket() {
	defer func() {
		_ = c.conn.Close()
		ClientHandler.UnregisterClient(c.name)
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
		if readErr == nil {
			continue
		}

		if websocket.IsUnexpectedCloseError(readErr, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
			log.Printf("Unexpected websocket close error: %v\n", readErr)
		}

		// If client fails to send ping messages
		if strings.Contains(strings.ToLower(readErr.Error()), "i/o timeout") {
			log.Printf("No ping received from client: %s\n", c.Name()) //nolint:gosec

			closeMessage := websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "No ping received!")

			writeErr := c.conn.WriteControl(websocket.CloseMessage, closeMessage, time.Now().Add(5*time.Second))
			if writeErr != nil {
				log.Printf("Error while sending close message: %v\n", writeErr)
			}
		} else if strings.Contains(strings.ToLower(readErr.Error()), "an existing connection was forcibly closed by the remote host") {
			log.Printf("Connection to client lost: %s\n", c.Name()) //nolint:gosec
		}

		log.Printf("Disconnecting client %s!\n", c.Name()) //nolint:gosec

		break
	}
}

// sanitizeInput removes newline and carriage-return characters from a
// string to prevent log-injection attacks (gosec G706).
func sanitizeInput(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")

	return s
}

// Name returns the name/identifier for this client.
func (c *WebsocketClient) Name() string {
	clientName := fmt.Sprintf("[%s] - ", c.name)

	realIP := sanitizeInput(c.realIPFromHeader)
	socket := net.JoinHostPort(c.hostIP, c.hostPort)

	// If the realIP is set and if it differs from the connection IP, return both the connection IP and the real IP.
	if realIP != "" && realIP != c.hostIP {
		clientName += fmt.Sprintf("%s (via %s)", socket, realIP)
	} else {
		clientName += socket
	}

	if c.userAgent != "" {
		ua := sanitizeInput(c.userAgent)
		clientName += fmt.Sprintf(" - '%s'", ua)
	}

	return clientName
}
