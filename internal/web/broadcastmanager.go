package web

import (
	"go-certstream-server/internal/certstream"
	"log"
	"sync"
)

type BroadcastManager struct {
	Broadcast  chan certstream.Entry
	clients    []*client
	clientLock sync.RWMutex
}

// registerClient adds a client to the list of clients of the BroadcastManager.
// The client will receive certificate broadcasts right after registration.
func (bm *BroadcastManager) registerClient(c *client) {
	bm.clientLock.Lock()
	bm.clients = append(bm.clients, c)
	log.Printf("Clients: %d, Capacity: %d\n", len(bm.clients), cap(bm.clients))
	bm.clientLock.Unlock()
}

// unregisterClient removes a client from the list of clients of the BroadcastManager.
// The client will no longer receive certificate broadcasts right after unregistering.
func (bm *BroadcastManager) unregisterClient(c *client) {
	bm.clientLock.Lock()
	for i, client := range bm.clients {
		if c == client {
			// Copy the last element of the slice to the position of the removed element
			// Then remove the last element by reslicing
			bm.clients[i] = bm.clients[len(bm.clients)-1]
			bm.clients[len(bm.clients)-1] = nil
			bm.clients = bm.clients[:len(bm.clients)-1]
			break
		}
	}
	bm.clientLock.Unlock()
}

// ClientFullCount returns the current number of clients connected to the service on the `full` endpoint.
func (bm *BroadcastManager) ClientFullCount() (count int64) {
	return bm.clientCountByType(SubTypeFull)
}

// ClientLiteCount returns the current number of clients connected to the service on the `lite` endpoint.
func (bm *BroadcastManager) ClientLiteCount() (count int64) {
	return bm.clientCountByType(SubTypeLite)
}

// ClientDomainsCount returns the current number of clients connected to the service on the `domains-only` endpoint.
func (bm *BroadcastManager) ClientDomainsCount() (count int64) {
	return bm.clientCountByType(SubTypeDomain)
}

// clientCountByType returns the current number of clients connected to the service on the endpoint matching the specified SubscriptionType.
func (bm *BroadcastManager) clientCountByType(subType SubscriptionType) (count int64) {
	bm.clientLock.RLock()
	defer bm.clientLock.RUnlock()
	for _, c := range bm.clients {
		if c.subType == subType {
			count++
		}
	}
	return count
}

// broadcaster is run in a goroutine and handles the dispatching of entries to clients.
func (bm *BroadcastManager) broadcaster() {
	for {
		entry := <-bm.Broadcast
		dataLite := entry.JSONLite()
		dataFull := entry.JSON()
		dataDomain := entry.JSONDomains()
		var data []byte

		bm.clientLock.RLock()
		for _, client := range bm.clients {
			switch client.subType {
			case SubTypeLite:
				data = dataLite
			case SubTypeFull:
				data = dataFull
			case SubTypeDomain:
				data = dataDomain
			}

			select {
			case client.broadcastChan <- data:
			default:
				log.Printf("Not providing client '%s' with cert because our buffer is full. The client can't keep up.\n", client.name)
			}
		}
		bm.clientLock.RUnlock()
	}
}
