package broadcast

import (
	"github.com/nsqio/go-nsq"

	"log"
	"time"
)

// NSQClient connects to a NSQ server in order to provide it with certificates.
type NSQClient struct {
	conn        *nsq.Producer // nsq connection
	addr        string
	topic       string
	isConnected bool
	BaseClient
}

// nullLogger is a logger that does not output anything.
// It is used to silence the NSQ logger.
type nullLogger struct{}

func (l nullLogger) Output(calldepth int, s string) error {
	// Do nothing, effectively silencing the logger
	return nil
}

// NewNSQClient creates a new NSQ client that immediately connects to the configured NSQ server
func NewNSQClient(subType SubscriptionType, addr, name, topic string, certBufferSize int) *NSQClient {
	log.Println("Initializing NSQ client...")

	// Instantiate a producer.
	conf := nsq.NewConfig()
	conn, err := nsq.NewProducer(addr, conf)
	if err != nil {
		log.Println(err)
	}

	log.Println("Connected to NSQ server at", addr)

	// Silence log output from NSQ
	conn.SetLogger(nullLogger{}, nsq.LogLevelError)

	nsqc := &NSQClient{
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
	nsqc.isConnected = true

	go nsqc.broadcastHandler()
	go nsqc.reconnectHandler()

	return nsqc
}

// reconnectHandler is a background job that attempts to reconnect to the NSQ server if the connection is lost.
func (c *NSQClient) reconnectHandler() {
	for {
		select {
		case <-c.stopChan:
			log.Println("Stopping reconnectHandler for nsq producer:", c.addr)
			return
		default:
			if c.isConnected {
				// If already connected or no connection exists, skip reconnection
				time.Sleep(5 * time.Second)
				continue
			}
			// Attempt to connect to the NSQ server
			err := c.conn.Ping()
			if err != nil {
				log.Printf("Reconnect to NSQ server failed: '%v'. Retrying in 5s...", err)
				time.Sleep(5 * time.Second)

				continue
			}

			c.isConnected = true
			log.Println("Reconnected to NSQ server at", c.addr)
		}
	}
}

// Each client has a broadcastHandler that runs in the background and sends out the broadcast messages to the client.
func (c *NSQClient) broadcastHandler() {
	// writeWait := 60 * time.Second

	defer func() {
		log.Println("Closing broadcast handler for nsq producer:", c.addr)
		// Gracefully stop the producer when appropriate (e.g. before shutting down the service)
		c.conn.Stop()
	}()

	for {
		select {
		case <-c.stopChan:
			return
		case message := <-c.broadcastChan:
			if !c.isConnected {
				continue
			}

			// Synchronously publish a single message to the specified topic.
			// Messages can also be sent asynchronously and/or in batches.
			err := c.conn.Publish(c.topic, message)
			if err != nil {
				log.Println("Error writing to NSQ topic:", err)
				c.isConnected = false
			}
		}
	}
}
