package certificatetransparency

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
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

// getAllLogs returns a list of all CT logs - those from the Google list, if not disabled -
// and additional logs provided via the config.
func getAllLogs(logListFetcher LogListFetcher) (loglist3.LogList, error) {
	var allLogs loglist3.LogList

	// Ability to disable default logs, if the user only wants to monitor custom logs.
	if !config.AppConfig.General.DisableDefaultLogs {
		var err error

		allLogs, err = logListFetcher.Fetch()
		if err != nil {
			log.Printf("Error fetching log list: %s\n", err)
			return loglist3.LogList{}, fmt.Errorf("failed to fetch log list: %w", err)
		}
	}

	// Add additional logs provided via the config, if any.
	for _, additionalLog := range config.AppConfig.General.AdditionalLogs {
		customLog := loglist3.Log{
			URL:         additionalLog.URL,
			Description: additionalLog.Description,
		}

		operatorFound := false

		for _, operator := range allLogs.Operators {
			// Only compare logs with the same operator
			if operator.Name != additionalLog.Operator {
				continue
			}

			operatorFound = true
			logFound := false

			// Check if user provided log is already in our loglist
			for _, ctlog := range operator.Logs {
				if ctlog.URL == additionalLog.URL {
					// Log already exists, skip it.
					logFound = true
					break
				}
			}

			if !logFound {
				// This works, since allLogs.Operators is a slice of pointers.
				operator.Logs = append(operator.Logs, &customLog)
			}

			break
		}

		if !operatorFound {
			newOperator := loglist3.Operator{
				Name: additionalLog.Operator,
				Logs: []*loglist3.Log{&customLog},
			}
			allLogs.Operators = append(allLogs.Operators, &newOperator)
		}
	}

	for _, additionalLog := range config.AppConfig.General.AdditionalTiledLogs {
		customLog := loglist3.TiledLog{
			MonitoringURL: additionalLog.URL,
			Description:   additionalLog.Description,
		}

		operatorFound := false

		for _, operator := range allLogs.Operators {
			if operator.Name == additionalLog.Operator {
				operatorFound = true
				logFound := false

				for _, tl := range operator.TiledLogs {
					if tl.MonitoringURL == additionalLog.URL {
						// Log already exists, skip it.
						logFound = true
						break
					}
				}

				if !logFound {
					// This works, since allLogs.Operators is a slice of pointers.
					operator.TiledLogs = append(operator.TiledLogs, &customLog)
				}

				break
			}
		}

		if !operatorFound {
			newOperator := loglist3.Operator{
				Name:      additionalLog.Operator,
				TiledLogs: []*loglist3.TiledLog{&customLog},
			}
			allLogs.Operators = append(allLogs.Operators, &newOperator)
		}
	}

	return allLogs, nil
}

func normalizeCtlogURL(input string) string {
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimSuffix(input, "/")

	return input
}
