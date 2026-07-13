package backoff

import (
	"testing"
	"time"
)

func TestErrorBackoff(t *testing.T) {
	backoffHandler := NewBackoff(1 * time.Second)

	for i := range 20 {
		backoffHandler(func() {
			test := i + 1
			t.Log("Hello World", test)
			time.Sleep(1100 * time.Millisecond)
		})
	}
}
