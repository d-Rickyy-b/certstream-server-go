package broadcast

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/backoff"
	"github.com/segmentio/kafka-go"
)

var (
	kafkaMaxBatchSize = 100
	kafkaMaxBatchWait = 1 * time.Second
	kafkaConnTimeout  = 5 * time.Second
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
	ctx, cancel := context.WithTimeout(context.Background(), kafkaConnTimeout)
	defer cancel()
	conn, err := kafka.DialLeader(ctx, "tcp", addr, topic, 0)
	if err != nil {
		log.Println("failed to connect to kafka:", err)
	}
	// TODO implement explicit topic creation

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

	var kafkaCompression kafka.Compression
	switch compression {
	case "gzip":
		kafkaCompression = kafka.Gzip
	case "snappy":
		kafkaCompression = kafka.Snappy
	case "lz4":
		kafkaCompression = kafka.Lz4
	case "none", "":
	default:
		log.Println("invalid compression type:", compression)
	}

	kc.compression = kafkaCompression

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
			ctx, cancel := context.WithTimeout(context.Background(), kafkaConnTimeout)
			defer cancel()
			conn, err := kafka.DialLeader(ctx, "tcp", c.addr, c.topic, 0)
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
		if c.conn != nil {
			if err := c.conn.Close(); err != nil {
				log.Println("failed to close conn:", err)
				return
			}
		}

		ClientHandler.UnregisterClient(c.name)
	}()

	backoffHandler := backoff.NewBackoff(60 * time.Second)
	batch := make([]kafka.Message, 0, kafkaMaxBatchSize)
	t := time.NewTimer(kafkaMaxBatchWait)

	for {
		select {
		case <-c.stopChan:
			return
		case message, ok := <-c.broadcastChan:
			if !ok {
				log.Println("broadcastChan closed for kafkaClient:", c.addr)
				return
			}

			// Drop messages if not connected
			if !c.isConnected {
				time.Sleep(5 * time.Second)
				continue
			}

			msg := kafka.Message{Value: message}
			batch = append(batch, msg)

			// Write batch if it reaches max size
			if len(batch) >= kafkaMaxBatchSize {
				err := c.writeBatch(batch)
				if err != nil {
					// Without using a backoff strategy, the errors would massively spam the log
					backoffHandler(func() {
						var netErr *net.OpError
						if errors.As(err, &netErr) {
							c.isConnected = false
						}

						log.Printf("Error writing messages to kafka: %v", err)
					})
				}

				batch = batch[:0]
				t.Reset(kafkaMaxBatchWait)
			}
		case <-t.C:
			// If batch size has not reached kafkaMaxBatchSize, write the batch after kafkaMaxBatchWait
			if len(batch) == 0 {
				continue
			}

			err := c.writeBatch(batch)
			if err != nil {
				// Without using a backoff strategy, the errors would massively spam the log
				backoffHandler(func() {
					var netErr *net.OpError
					if errors.As(err, &netErr) {
						c.isConnected = false
					}

					log.Printf("Error writing messages to kafka: %v", err)
				})
			}

			batch = batch[:0]
		}
	}
}

// writeBatch writes a batch of messages to Kafka, handling exponential backoff and connection state
func (c *KafkaClient) writeBatch(batch []kafka.Message) error {
	if len(batch) == 0 {
		return nil
	}

	if c.conn == nil || !c.isConnected {
		return errors.New("no connection to kafka")
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(kafkaConnTimeout))

	_, err := c.conn.WriteCompressedMessages(
		c.compression.Codec(),
		batch...,
	)
	if err != nil {
		// Treat kafka errors specially
		var kafkaErr kafka.Error
		if errors.As(err, &kafkaErr) {
			if errors.Is(kafkaErr, kafka.MessageSizeTooLarge) {
				log.Printf("Message size is too large for kafka broker '%s' - reducing batch size to %d", c.addr, kafkaMaxBatchSize/2)
				kafkaMaxBatchSize = kafkaMaxBatchSize / 2
				// TODO: currently there is no retry mechanism implemented. We should try to resend the current batch with the reduced batch size.
			}
		}

		return err
	}
	return nil
}
