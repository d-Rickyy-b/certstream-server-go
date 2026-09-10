package broadcast

import "testing"

func newDispatcherTestWebsocketClient(name string) *WebsocketClient {
	return &WebsocketClient{
		hostIP:   "127.0.0.1",
		hostPort: "12345",
		BaseClient: &BaseClient{
			broadcastChan: make(chan []byte, 1),
			name:          name,
			subType:       SubTypeFull,
		},
	}
}

func TestDispatcherUnregisterWebsocketClient(t *testing.T) {
	d := &Dispatcher{}
	client := newDispatcherTestWebsocketClient("client-1")

	d.RegisterClient(client)
	if got := len(d.clients); got != 1 {
		t.Fatalf("expected 1 registered client, got %d", got)
	}

	d.UnregisterClient(client)
	if got := len(d.clients); got != 0 {
		t.Fatalf("expected 0 registered clients after unregister, got %d", got)
	}
}

func TestDispatcherUnregisterWebsocketClientDoesNotPanicOnNilStopChan(t *testing.T) {
	d := &Dispatcher{}
	client := newDispatcherTestWebsocketClient("client-2")

	d.RegisterClient(client)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unregistering websocket client panicked: %v", r)
		}
	}()

	d.UnregisterClient(client)
}
