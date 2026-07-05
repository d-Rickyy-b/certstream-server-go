package certificatetransparency

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
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
	excludedOperators := []string{}
	excludedLogs := []string{}

	// Extract excluded logs from the config.
	for _, excludedLog := range config.AppConfig.General.ExcludedLogs {
		if excludedLog.URL == "" {
			// Exclude whole operator
			excludedOperators = append(excludedOperators, excludedLog.Operator)
		} else {
			// Exclude only this specific URL (normalize for comparison)
			excludedLogs = append(excludedLogs, normalizeCtlogURL(excludedLog.URL))
		}
	}

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
			if operator.Name != additionalLog.Operator {
				continue
			}

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

		if !operatorFound {
			newOperator := loglist3.Operator{
				Name:      additionalLog.Operator,
				TiledLogs: []*loglist3.TiledLog{&customLog},
			}
			allLogs.Operators = append(allLogs.Operators, &newOperator)
		}
	}

	// Remove excluded operators and logs after we've added custom logs.
	if len(excludedOperators) > 0 || len(excludedLogs) > 0 {
		filteredOperators := []*loglist3.Operator{}

		for _, operator := range allLogs.Operators {
			// Skip whole operator if it's excluded
			if slices.Contains(excludedOperators, operator.Name) {
				continue
			}

			// Filter normal logs
			if len(operator.Logs) > 0 {
				keepLogs := []*loglist3.Log{}
				for _, l := range operator.Logs {
					if slices.Contains(excludedLogs, normalizeCtlogURL(l.URL)) {
						// excluded, skip
						log.Println("Excluding log based on the config: ", operator.Name, normalizeCtlogURL(l.URL))
						continue
					}

					keepLogs = append(keepLogs, l)
				}

				operator.Logs = keepLogs
			}

			// Filter tiled logs
			if len(operator.TiledLogs) > 0 {
				keepTiled := []*loglist3.TiledLog{}
				for _, tl := range operator.TiledLogs {
					if slices.Contains(excludedLogs, normalizeCtlogURL(tl.MonitoringURL)) {
						// excluded, skip
						log.Println("Excluding tiled log based on the config: ", operator.Name, normalizeCtlogURL(tl.MonitoringURL))
						continue
					}

					keepTiled = append(keepTiled, tl)
				}

				operator.TiledLogs = keepTiled
			}

			filteredOperators = append(filteredOperators, operator)
		}

		allLogs.Operators = filteredOperators
	}

	return allLogs, nil
}

func normalizeCtlogURL(input string) string {
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimSuffix(input, "/")

	return input
}
