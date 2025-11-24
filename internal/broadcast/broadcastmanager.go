package broadcast

import (
	"log"
	"sync"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
)

// ClientHandler dispatches certificate entries to registered clients.
var ClientHandler *Dispatcher

type Dispatcher struct {
	MessageQueue chan models.Entry
	clients      []CertProcessor
	clientLock   sync.RWMutex
}

// NewDispatcher creates a new Dispatcher instance and assigns it to the ClientHandler variable.
func NewDispatcher() *Dispatcher {
	d := &Dispatcher{}
	d.MessageQueue = make(chan models.Entry, config.AppConfig.General.BufferSizes.Dispatcher)
	ClientHandler = d

	return d
}

// RegisterClient adds a client to the list of clients of the Dispatcher.
// The client will receive certificate broadcasts right after registration.
func (bm *Dispatcher) RegisterClient(c CertProcessor) {
	// TODO: check if the client is already registered
	bm.clientLock.Lock()
	bm.clients = append(bm.clients, c)
	log.Printf("Added new client. Clients: %d, Capacity: %d\n", len(bm.clients), cap(bm.clients))
	bm.clientLock.Unlock()
}

// UnregisterClient removes a client from the list of clients of the Dispatcher.
// The client will no longer receive certificate broadcasts right after unregistering.
func (bm *Dispatcher) UnregisterClient(clientName string) {
	bm.clientLock.Lock()

	for i, client := range bm.clients {
		if clientName == client.Name() {
			// Copy the last element of the slice to the position of the removed element
			// Then remove the last element by re-slicing
			bm.clients[i] = bm.clients[len(bm.clients)-1]
			bm.clients[len(bm.clients)-1] = nil
			bm.clients = bm.clients[:len(bm.clients)-1]

			// Close the broadcast channel of the client, otherwise this leads to a memory leak
			client.Close()

			break
		}
	}

	bm.clientLock.Unlock()
}

// ClientFullCount returns the current number of clients connected to the service on the `full` endpoint.
func (bm *Dispatcher) ClientFullCount() (count int64) {
	return bm.clientCountByType(SubTypeFull)
}

// ClientLiteCount returns the current number of clients connected to the service on the `lite` endpoint.
func (bm *Dispatcher) ClientLiteCount() (count int64) {
	return bm.clientCountByType(SubTypeLite)
}

// ClientDomainsCount returns the current number of clients connected to the service on the `domains-only` endpoint.
func (bm *Dispatcher) ClientDomainsCount() (count int64) {
	return bm.clientCountByType(SubTypeDomain)
}

// clientCountByType returns the current number of clients connected to the service on the endpoint matching
// the specified SubscriptionType.
func (bm *Dispatcher) clientCountByType(subType SubscriptionType) (count int64) {
	bm.clientLock.RLock()
	defer bm.clientLock.RUnlock()

	for _, c := range bm.clients {
		if c.SubType() == subType {
			count++
		}
	}

	return count
}

// GetSkippedCerts returns a map of client names to the number of skipped certificates for each client.
func (bm *Dispatcher) GetSkippedCerts() map[string]uint64 {
	bm.clientLock.RLock()
	defer bm.clientLock.RUnlock()

	skippedCerts := make(map[string]uint64, len(bm.clients))
	for _, c := range bm.clients {
		skippedCerts[c.Name()] = c.SkippedCerts()
	}

	return skippedCerts
}

// broadcaster is run in a goroutine and handles the dispatching of certs to clients.
func (bm *Dispatcher) broadcaster() {
	for {
		var data []byte

		entry := <-bm.MessageQueue
		dataLite := entry.JSONLite()
		dataFull := entry.JSON()
		dataDomain := entry.JSONDomains()

		bm.clientLock.RLock()

		for _, c := range bm.clients {
			switch c.SubType() {
			case SubTypeLite:
				data = dataLite
			case SubTypeFull:
				data = dataFull
			case SubTypeDomain:
				data = dataDomain
			default:
				// This should never happen, but if it does, we log it and skip the client.
				log.Printf("Unknown subscription type '%d' for client '%s'. Skipping this client!\n", c.SubType(), c.Name())
				continue
			}

			c.Write(data)
		}

		bm.clientLock.RUnlock()
	}
}

// Start starts the broadcaster goroutine.
func (bm *Dispatcher) Start() {
	go bm.broadcaster()
	log.Println("Dispatcher started. Listening for certificate entries...")
}
