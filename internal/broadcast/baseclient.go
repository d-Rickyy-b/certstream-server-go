package broadcast

import "log"

// BaseClient defines the basic structure for a client that can receive broadcast messages.
// Other client types can embed this struct to inherit its functionality.
type BaseClient struct {
	broadcastChan chan []byte
	stopChan      chan struct{}
	name          string
	subType       SubscriptionType
	skippedCerts  uint64
}

// Close cleans up the client's resources by closing the stop and broadcast channels.
func (c *BaseClient) Close() {
	close(c.stopChan)
	close(c.broadcastChan)
}

// Name returns the name of the client.
func (c *BaseClient) Name() string {
	return c.name
}

// SubType returns the subscription type of the client.
func (c *BaseClient) SubType() SubscriptionType {
	return c.subType
}

// SkippedCerts returns the number of certificates that were skipped due to the client's broadcast channel being full.
func (c *BaseClient) SkippedCerts() uint64 {
	return c.skippedCerts
}

// Write sends a message to the client's broadcast channel.
// If the channel is full, it increments the skippedCerts counter and logs a message.
func (c *BaseClient) Write(data []byte) {
	select {
	case c.broadcastChan <- data:
	default:
		// Default case is executed if the client's broadcast channel is full.
		c.skippedCerts++
		if c.skippedCerts%1000 == 1 {
			log.Printf("Not providing client '%s' with cert because client's buffer is full. The client can't keep up. Skipped certs: %d\n", c.name, c.skippedCerts)
		}
	}
}
