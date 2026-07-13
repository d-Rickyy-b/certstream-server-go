package backoff

import (
	"sync"
	"time"
)

// NewBackoff returns a function that implements exponential backoff for the given reset window.
func NewBackoff(resetWindow time.Duration) func(target func()) {
	mu := sync.Mutex{}
	var errorCount int
	var errorLastTime time.Time
	errorLogResetWindow := resetWindow

	return func(target func()) {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()

		// Reset counter if enough time has passed since the last error
		if now.Sub(errorLastTime) > errorLogResetWindow {
			errorCount = 0
		}

		errorCount++
		errorLastTime = now

		if errorCount == 1 || (errorCount&(errorCount-1)) == 0 {
			target()
		}
	}
}
