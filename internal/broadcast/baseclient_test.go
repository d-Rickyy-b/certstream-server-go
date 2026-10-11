package broadcast

import "testing"

func TestBaseClientCloseIsSafeForNilChannelsAndRepeatedCalls(t *testing.T) {
	client := &BaseClient{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BaseClient.Close() panicked: %v", r)
		}
	}()

	client.Close()
	client.Close()
}

func TestBaseClientWriteAfterCloseDoesNotPanic(t *testing.T) {
	client := &BaseClient{
		broadcastChan: make(chan []byte, 1),
		stopChan:      make(chan struct{}),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BaseClient.Write() after Close() panicked: %v", r)
		}
	}()

	client.Close()
	client.Write([]byte("data"))

	if got := len(client.broadcastChan); got != 0 {
		t.Fatalf("expected no message to be queued after Close(), got %d", got)
	}
}
