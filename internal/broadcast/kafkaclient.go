package broadcast

import (
	"context"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
)

const (
	maxBatchSize = 50
	maxBatchWait = 60 * time.Second
	writeWait    = 60 * time.Second
)

// KafkaClient connects to a Kafka server in order to provide it with certificates.
type KafkaClient struct {
	conn        *kafka.Conn // Kafka connection
	addr        string
	topic       string
	compression kafka.Compression
	isConnected bool
	BaseClient
}

// NewKafkaClient creates a new Kafka client that immediately connects to the configured Kafka server.
func NewKafkaClient(subType SubscriptionType, addr, name, topic, compression string, certBufferSize int) *KafkaClient {
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

	switch compression {
	case "gzip":
		kc.compression = kafka.Gzip
	case "snappy":
		kc.compression = kafka.Snappy
	case "lz4":
		kc.compression = kafka.Lz4
	case "none":
	default:
		log.Println("invalid compression type:", compression)
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
	defer func() {
		log.Println("Closing broadcast handler for kafka producer:", c.addr)
		if err := c.conn.Close(); err != nil {
			log.Println("failed to close writer:", err)
		}

		ClientHandler.UnregisterClient(c.name)
	}()

	batch := make([]kafka.Message, 0, maxBatchSize)
	t := time.NewTimer(maxBatchWait)

	for {
		select {
		case <-c.stopChan:
			return
		case message := <-c.broadcastChan:
			// Drop messages if not connected
			if !c.isConnected {
				continue
			}

			msg := kafka.Message{Value: message}
			batch = append(batch, msg)

			// Write batch if it reaches max size
			if len(batch) >= maxBatchSize {
				c.writeBatch(batch)
				batch = batch[:0]
				t.Reset(maxBatchWait)
			}
		case <-t.C:
			if len(batch) == 0 {
				continue
			}

			// Write any remaining batch after maxBatchWait
			c.writeBatch(batch)
			batch = batch[:0]
		}
	}
}

func (c *KafkaClient) writeBatch(batch []kafka.Message) {
	if len(batch) == 0 {
		return
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	_, err := c.conn.WriteMessages(batch...)
	if err != nil {
		c.isConnected = false
		log.Println("Failed to write messages to kafka:", err)
	}
}
