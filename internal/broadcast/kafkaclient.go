package broadcast

import (
	"context"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
)

const (
	TOPIC = "certstream"
)

// KafkaClient connects to a Kafka server in order to provide it with certificates.
type KafkaClient struct {
	conn        *kafka.Conn // Kafka connection
	addr        string
	topic       string
	isConnected bool
	BaseClient
}

// NewKafkaClient creates a new Kafka client that immediately connects to the configured Kafka server.
func NewKafkaClient(subType SubscriptionType, addr, name, topic string, certBufferSize int) *KafkaClient {
	// Connect to the Kafka server
	conn, err := kafka.DialLeader(context.Background(), "tcp", addr, topic, 0)
	if err != nil {
		log.Println("failed to connect to kafka:", err)
	}

	kc := &KafkaClient{
		conn:  conn,
		addr:  addr,
		topic: topic,
		BaseClient: BaseClient{
			broadcastChan: make(chan []byte, certBufferSize),
			stopChan:      make(chan struct{}),
			name:          name,
			subType:       subType,
		},
	}

	go kc.broadcastHandler()
	go kc.reconnectHandler()

	return kc
}

// reconnectHandler is a background job that attempts to reconnect to the Kafka server if the connection is lost.
func (c *KafkaClient) reconnectHandler() {
	for {
		select {
		case <-c.stopChan:
			log.Println("Stopping reconnectHandler for kafka producer:", c.addr)
			c.conn.Close()

			return
		default:
			if c.isConnected {
				// If already connected or no connection exists, skip reconnection
				time.Sleep(5 * time.Second)
				continue
			}

			// Attempt to connect to the Kafka server
			conn, err := kafka.DialLeader(context.Background(), "tcp", c.addr, c.topic, 0)
			if err != nil {
				log.Printf("Reconnect failed: %v. Retrying in 5s...", err)
				time.Sleep(5 * time.Second)

				continue
			}
			// Close old connection if exists
			if c.conn != nil {
				_ = c.conn.Close()
			}
			c.conn = conn
			c.isConnected = true
			log.Println("Reconnected to Kafka at", c.addr)
		}
	}
}

// Each client has a broadcastHandler that runs in the background and sends out the broadcast messages to the client.
func (c *KafkaClient) broadcastHandler() {
	writeWait := 60 * time.Second

	defer func() {
		log.Println("Closing broadcast handler for kafka producer:", c.addr)
		if err := c.conn.Close(); err != nil {
			log.Println("failed to close writer:", err)
		}

		ClientHandler.UnregisterClient(c.name)
	}()

	for {
		select {
		case <-c.stopChan:
			return
		case message := <-c.broadcastChan:
			if !c.isConnected {
				continue
			}

			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))

			c.conn.Broker()
			_, err := c.conn.WriteMessages(
				kafka.Message{Value: message},
			)
			if err != nil {
				c.isConnected = false
				log.Println("Failed to write messages to kafka:", err)
			}
		}
	}
}
