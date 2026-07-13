package broadcast

// CertProcessor defines the interface for processing certificate messages.
// Different implementations can be used for different types of clients, such as WebSocket clients, kafka, or other message queues for example.
type CertProcessor interface {
	// Write sends a message to the client's broadcast channel.
	Write(message []byte)
	// Close closes the client's connection and cleans up resources.
	Close()

	// To obtain client details, there are getter methods for several values
	Name() string
	SubType() SubscriptionType
	SkippedCerts() uint64
}

const (
	// SubTypeFull represents full certificate updates.
	SubTypeFull SubscriptionType = iota
	// SubTypeLite represents certificate updates with less details.
	SubTypeLite
	// SubTypeDomain represents updates that only include domain information.
	SubTypeDomain
)

type SubscriptionType int
