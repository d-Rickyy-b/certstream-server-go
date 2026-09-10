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
