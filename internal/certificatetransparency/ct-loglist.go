package certificatetransparency

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

var googleLogListFetcher = NewHTTPLogListFetcher(loglist3.LogListURL)

type LogListFetcher interface {
	Fetch() (loglist3.LogList, error)
}

type HTTPLogListFetcher struct {
	LogListURL string
}

func NewHTTPLogListFetcher(url string) *HTTPLogListFetcher {
	return &HTTPLogListFetcher{LogListURL: url}
}

// Fetch fetches the list of all CT logs from the provided LogList URL.
func (f *HTTPLogListFetcher) Fetch() (loglist3.LogList, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	httpClient := newHTTPClient()

	req, newReqErr := http.NewRequestWithContext(ctx, http.MethodGet, f.LogListURL, nil)
	if newReqErr != nil {
		return loglist3.LogList{}, fmt.Errorf("failed to create loglist request: %w", newReqErr)
	}

	// Download the list of all logs from ctLogInfo and decode JSON
	resp, reqErr := httpClient.Do(req)
	if reqErr != nil {
		return loglist3.LogList{}, fmt.Errorf("failed to execute loglist request: %w", reqErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return loglist3.LogList{}, fmt.Errorf("%w: unexpected status code %d", ErrRequestFailed, resp.StatusCode)
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return loglist3.LogList{}, fmt.Errorf("failed reading response body: %w", readErr)
	}

	allLogs, parseErr := loglist3.NewFromJSON(bodyBytes)
	if parseErr != nil {
		return loglist3.LogList{}, fmt.Errorf("failed parsing response body: %w", parseErr)
	}

	return *allLogs, nil
}
