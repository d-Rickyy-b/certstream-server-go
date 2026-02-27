package certificatetransparency

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadCTIndex_DoesNotDeadlockWhenFileMissing(t *testing.T) {
	metrics := LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	ctIndexPath := filepath.Join(t.TempDir(), "ct_index.json")

	done := make(chan struct{})
	go func() {
		metrics.LoadCTIndex(ctIndexPath)
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("LoadCTIndex appears to deadlock when index file is missing")
	}
}
