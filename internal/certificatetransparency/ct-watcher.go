package certificatetransparency

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/scanner"
)

var (
	errCreatingClient    = errors.New("failed to create JSON client")
	errFetchingSTHFailed = errors.New("failed to fetch STH")
	userAgent            = fmt.Sprintf("Certstream Server v%s (github.com/d-Rickyy-b/certstream-server-go)", config.Version)
)

// Watcher describes a component that watches for new certificates in a CT log.
type Watcher struct {
	workers    []*worker
	workersMu  sync.RWMutex
	wg         sync.WaitGroup
	context    context.Context
	certChan   chan models.Entry
	cancelFunc context.CancelFunc
}

// NewWatcher creates a new Watcher.
func NewWatcher(certChan chan models.Entry) *Watcher {
	return &Watcher{
		certChan: certChan,
	}
}

// Start starts the watcher. This method is blocking.
func (w *Watcher) Start() {
	w.context, w.cancelFunc = context.WithCancel(context.Background())

	// Create new certChan if it doesn't exist yet
	if w.certChan == nil {
		w.certChan = make(chan models.Entry, 5000)
	}

	if config.AppConfig.General.Recovery.Enabled {
		ctIndexFilePath, err := filepath.Abs(config.AppConfig.General.Recovery.CTIndexFile)
		if err != nil {
			log.Printf("Error getting absolute path for CT index file: '%s', %s\n", config.AppConfig.General.Recovery.CTIndexFile, err)
			return
		}
		// Load Saved CT Indexes
		metrics.LoadCTIndex(ctIndexFilePath)
		// Save CTIndexes at regular intervals
		go metrics.SaveCertIndexesAtInterval(time.Second*30, ctIndexFilePath) // save indexes every X seconds
	}

	// initialize the watcher with currently available logs
	w.updateLogs()

	log.Println("Started CT watcher")
	go certHandler(w.certChan)
	go w.watchNewLogs()

	// Wait for all workers to finish
	w.wg.Wait()
	close(w.certChan)
}

// watchNewLogs monitors the ct log list for new logs and starts a worker for each new log found.
// This method is blocking. It can be stopped by cancelling the context.
func (w *Watcher) watchNewLogs() {
	// Check for new logs once every hour
	ticker := time.NewTicker(1 * time.Hour)
	for {
		select {
		case <-ticker.C:
			w.updateLogs()
		case <-w.context.Done():
			ticker.Stop()
			return
		}
	}
}

// updateLogs checks the transparency log list for new logs and adds new 0workers for those to the watcher.
func (w *Watcher) updateLogs() {
	// Get a list of urls of all CT logs
	logList, err := getAllLogs()
	if err != nil {
		log.Println(err)
		return
	}

	w.addNewlyAvailableLogs(logList)

	if *config.AppConfig.General.DropOldLogs {
		w.dropRemovedLogs(logList)
	}
}

// addNewlyAvailableLogs checks the transparency log list for new Log servers and adds workers for those to the watcher.
func (w *Watcher) addNewlyAvailableLogs(logList loglist3.LogList) {
	log.Println("Checking for new ct logs...")

	w.workersMu.Lock()
	defer w.workersMu.Unlock()
	newCTs := 0

	// Check the ct log list for new, unwatched logs
	// For each CT log, create a worker and start downloading certs
	for _, operator := range logList.Operators {
		// Iterate over each log of the operator
		for _, transparencyLog := range operator.Logs {
			newURL := normalizeCtlogURL(transparencyLog.URL)

			if transparencyLog.State.LogStatus() == loglist3.RetiredLogStatus {
				log.Printf("Skipping retired CT log: %s\n", newURL)
				continue
			}

			// Check if the log is already being watched
			alreadyWatched := false

			for _, ctWorker := range w.workers {
				workerURL := normalizeCtlogURL(ctWorker.ctURL)
				if workerURL == newURL {
					alreadyWatched = true
					break
				}
			}

			// If the log is already being watched, continue
			if alreadyWatched {
				continue
			}

			w.wg.Add(1)
			newCTs++

			// Metrics are initialized with 0.
			// Only if recovery is enabled, it is initialized with the last saved index.
			lastCTIndex := metrics.GetCTIndex(normalizeCtlogURL(transparencyLog.URL))
			ctWorker := worker{
				name:         transparencyLog.Description,
				operatorName: operator.Name,
				ctURL:        transparencyLog.URL,
				entryChan:    w.certChan,
				ctIndex:      lastCTIndex,
			}
			w.workers = append(w.workers, &ctWorker)
			metrics.Init(operator.Name, normalizeCtlogURL(transparencyLog.URL))

			// Start a goroutine for each worker
			go func() {
				defer w.wg.Done()
				ctWorker.startDownloadingCerts(w.context)
				w.discardWorker(&ctWorker)
			}()
		}
	}

	log.Printf("New ct logs found: %d\n", newCTs)
	log.Printf("Currently monitored ct logs: %d\n", len(w.workers))
}

// discardWorker removes a worker from the watcher's list of workers.
// This needs to be done when a worker stops.
func (w *Watcher) discardWorker(worker *worker) {
	log.Println("Removing worker for CT log:", worker.ctURL)

	w.workersMu.Lock()
	defer w.workersMu.Unlock()

	for i, wo := range w.workers {
		if wo == worker {
			w.workers = append(w.workers[:i], w.workers[i+1:]...)
			return
		}
	}
}

// dropRemovedLogs checks if any of the currently monitored logs are no longer in the log list or are retired.
// If they are not, the CT Logs are probably no longer relevant and the corresponding workers will be stopped.
func (w *Watcher) dropRemovedLogs(logList loglist3.LogList) {
	removedCTs := 0

	// Iterate over all workers and check if they are still in the logList
	// If they are not, the CT Logs are probably no longer relevant.
	// We should stop the worker if that didn't already happen.
	for _, ctWorker := range w.workers {
		workerURL := normalizeCtlogURL(ctWorker.ctURL)

		onLogList := false
		for _, operator := range logList.Operators {
			if ctWorker.operatorName != operator.Name {
				// This operator is not the one we're looking for
				continue
			}

			// Iterate over each log of the operator
			for _, transparencyLog := range operator.Logs {
				// Remove retired logs from the list
				if transparencyLog.State.LogStatus() == loglist3.RetiredLogStatus {
					// Skip retired logs
					continue
				}

				// Check if the log is already being watched
				logListURL := normalizeCtlogURL(transparencyLog.URL)
				if workerURL == logListURL {
					onLogList = true
					break
				}
			}

			// Prevent further loop iterations
			if onLogList {
				break
			}
		}

		// Make sure to not drop logs that are defined locally in the additional logs list
		for _, additionalLogConfig := range config.AppConfig.General.AdditionalLogs {
			additionalLogListURL := normalizeCtlogURL(additionalLogConfig.URL)
			if workerURL == additionalLogListURL {
				onLogList = true
				break
			}
		}

		// If the log is not in the loglist, stop the worker
		if !onLogList {
			log.Printf("Stopping worker. CT URL not found in LogList or retired: '%s'\n", ctWorker.ctURL)
			removedCTs++
			ctWorker.stop()
		}
	}

	log.Printf("Removed ct logs: %d\n", removedCTs)
	log.Printf("Currently monitored ct logs: %d\n", len(w.workers))
}

// Stop stops the watcher.
func (w *Watcher) Stop() {
	log.Printf("Stopping watcher\n")

	// Store current CT Indexes before shutting down
	filePath := config.AppConfig.General.Recovery.CTIndexFile
	tempFilePath := fmt.Sprintf("%s.tmp", filePath)
	metrics.SaveCertIndexes(tempFilePath, filePath)

	w.cancelFunc()
}

// CreateIndexFile creates a ct_index.json file based on the current STHs of all availble logs.
func (w *Watcher) CreateIndexFile(filePath string) error {
	logs, err := getAllLogs()
	if err != nil {
		return err
	}

	w.context, w.cancelFunc = context.WithCancel(context.Background())
	log.Println("Fetching current STH for all logs...")
	for _, operator := range logs.Operators {
		// Iterate over each log of the operator
		for _, transparencyLog := range operator.Logs {
			// Check if the log is already being watched
			metrics.Init(operator.Name, normalizeCtlogURL(transparencyLog.URL))
			log.Println("Fetching STH for", normalizeCtlogURL(transparencyLog.URL))

			hc := http.Client{Timeout: 5 * time.Second}
			jsonClient, e := client.New(transparencyLog.URL, &hc, jsonclient.Options{UserAgent: userAgent})
			if e != nil {
				log.Printf("Error creating JSON client: %s\n", e)
				continue
			}

			sth, getSTHerr := jsonClient.GetSTH(w.context)
			if getSTHerr != nil {
				// TODO this can happen due to a 429 error. We should retry the request
				log.Printf("Could not get STH for '%s': %s\n", transparencyLog.URL, getSTHerr)
				continue
			}

			metrics.SetCTIndex(normalizeCtlogURL(transparencyLog.URL), sth.TreeSize)
		}
	}
	w.cancelFunc()

	tempFilePath := fmt.Sprintf("%s.tmp", filePath)
	metrics.SaveCertIndexes(tempFilePath, filePath)
	log.Println("Index file saved to", filePath)

	return nil
}

// A worker processes a single CT log.
type worker struct {
	name         string
	operatorName string
	ctURL        string
	entryChan    chan models.Entry
	ctIndex      uint64
	mu           sync.Mutex
	running      bool
	cancel       context.CancelFunc
}

// startDownloadingCerts starts downloading certificates from the CT log. This method is blocking.
func (w *worker) startDownloadingCerts(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)

	// Normalize CT URL. We remove trailing slashes and prepend "https://" if it's not already there.
	w.ctURL = strings.TrimRight(w.ctURL, "/")
	if !strings.HasPrefix(w.ctURL, "https://") && !strings.HasPrefix(w.ctURL, "http://") {
		w.ctURL = "https://" + w.ctURL
	}

	log.Printf("Initializing worker for CT log: %s\n", w.ctURL)
	defer log.Printf("Stopping worker for CT log: %s\n", w.ctURL)

	w.mu.Lock()
	if w.running {
		log.Printf("Worker for '%s' already running\n", w.ctURL)
		w.mu.Unlock()

		return
	}

	w.running = true
	defer func() { w.running = false }()
	w.mu.Unlock()

	for {
		log.Printf("Starting worker for CT log: %s\n", w.ctURL)
		workerErr := w.runWorker(ctx)
		if workerErr != nil {
			if errors.Is(workerErr, errFetchingSTHFailed) {
				// TODO this could happen due to a 429 error. We should retry the request
				log.Printf("Worker for '%s' failed - could not fetch STH\n", w.ctURL)
				return
			} else if errors.Is(workerErr, errCreatingClient) {
				log.Printf("Worker for '%s' failed - could not create client\n", w.ctURL)
				return
			} else if strings.Contains(workerErr.Error(), "no such host") {
				log.Printf("Worker for '%s' failed to resolve host: %s\n", w.ctURL, workerErr)
				return
			}

			log.Printf("Worker for '%s' failed with unexpected error: %s\n", w.ctURL, workerErr)
		}

		// Check if the context was cancelled
		select {
		case <-ctx.Done():
			log.Printf("Context was cancelled; Stopping worker for '%s'\n", w.ctURL)

			return
		default:
			log.Printf("Worker for '%s' sleeping for 5 seconds due to error\n", w.ctURL)
			time.Sleep(5 * time.Second)
			log.Printf("Restarting worker for '%s'\n", w.ctURL)

			continue
		}
	}
}

func (w *worker) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.cancel()
}

// runWorker runs a single worker for a single CT log. This method is blocking.
func (w *worker) runWorker(ctx context.Context) error {
	hc := http.Client{Timeout: 30 * time.Second}
	jsonClient, e := client.New(w.ctURL, &hc, jsonclient.Options{UserAgent: userAgent})
	if e != nil {
		log.Printf("Error creating JSON client: %s\n", e)
		return errCreatingClient
	}

	// If recovery is enabled and the CT index is set, we start at the saved index. Otherwise we start at the latest STH.
	validSavedCTIndexExists := config.AppConfig.General.Recovery.Enabled
	if !validSavedCTIndexExists {
		sth, getSTHerr := jsonClient.GetSTH(ctx)
		if getSTHerr != nil {
			// TODO this can happen due to a 429 error. We should retry the request
			log.Printf("Could not get STH for '%s': %s\n", w.ctURL, getSTHerr)
			return errFetchingSTHFailed
		}
		// Start at the latest STH to skip all the past certificates
		w.ctIndex = sth.TreeSize
	}

	certScanner := scanner.NewScanner(jsonClient, scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     100,
			ParallelFetch: 1,
			StartIndex:    int64(w.ctIndex),
			Continuous:    true,
		},
		Matcher:     scanner.MatchAll{},
		PrecertOnly: false,
		NumWorkers:  1,
		BufferSize:  config.AppConfig.General.BufferSizes.CTLog,
	})

	scanErr := certScanner.Scan(ctx, w.foundCertCallback, w.foundPrecertCallback)
	if scanErr != nil {
		log.Println("Scan error: ", scanErr)
		return scanErr
	}

	log.Printf("Exiting worker %s without error!\n", w.ctURL)

	return nil
}

// foundCertCallback is the callback that handles cases where new regular certs are found.
func (w *worker) foundCertCallback(rawEntry *ct.RawLogEntry) {
	entry, parseErr := ParseCertstreamEntry(rawEntry, w.operatorName, w.name, w.ctURL)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}

	entry.Data.UpdateType = "X509LogEntry"
	w.entryChan <- entry

	atomic.AddInt64(&processedCerts, 1)
}

// foundPrecertCallback is the callback that handles cases where new precerts are found.
func (w *worker) foundPrecertCallback(rawEntry *ct.RawLogEntry) {
	entry, parseErr := ParseCertstreamEntry(rawEntry, w.operatorName, w.name, w.ctURL)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}

	entry.Data.UpdateType = "PrecertLogEntry"
	w.entryChan <- entry

	atomic.AddInt64(&processedPrecerts, 1)
}

// certHandler takes the entries out of the entryChan channel and broadcasts them to all clients.
// Only a single instance of the certHandler runs per certstream server.
func certHandler(entryChan chan models.Entry) {
	var processed int64

	for {
		entry := <-entryChan
		processed++

		if processed%1000 == 0 {
			log.Printf("Processed %d entries | Queue length: %d\n", processed, len(entryChan))
			// Every thousandth entry, we store one certificate as example
			web.SetExampleCert(entry)
		}

		// Run json encoding in the background and send the result to the clients.
		web.ClientHandler.Broadcast <- entry

		// Update metrics
		url := entry.Data.Source.NormalizedURL
		operator := entry.Data.Source.Operator
		index := entry.Data.CertIndex

		metrics.Inc(operator, url, index)
	}
}

// getGoogleLogList fetches the list of all CT logs from Google Chromes CT LogList.
func getGoogleLogList() (loglist3.LogList, error) {
	// Download the list of all logs from ctLogInfo and decode json
	resp, err := http.Get(loglist3.LogListURL)
	if err != nil {
		return loglist3.LogList{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return loglist3.LogList{}, errors.New("failed to download loglist")
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Panic(readErr)
	}

	allLogs, parseErr := loglist3.NewFromJSON(bodyBytes)
	if parseErr != nil {
		return loglist3.LogList{}, parseErr
	}

	return *allLogs, nil
}

// getAllLogs returns a list of all CT logs.
func getAllLogs() (loglist3.LogList, error) {
	var allLogs loglist3.LogList
	var err error

	// Ability to disable default logs, if the user only wants to monitor custom logs.
	if !config.AppConfig.General.DisableDefaultLogs {
		allLogs, err = getGoogleLogList()
		if err != nil {
			log.Printf("Error fetching log list from Google: %s\n", err)
			return loglist3.LogList{}, fmt.Errorf("failed to fetch log list from Google: %w", err)
		}
	}

	// Add manually added logs from config to the allLogs list
	if config.AppConfig.General.AdditionalLogs == nil {
		return allLogs, nil
	}

	for _, additionalLog := range config.AppConfig.General.AdditionalLogs {
		customLog := loglist3.Log{
			URL:         additionalLog.URL,
			Description: additionalLog.Description,
		}

		operatorFound := false
		for _, operator := range allLogs.Operators {
			if operator.Name == additionalLog.Operator {
				// TODO Check if the log is already in the list
				operator.Logs = append(operator.Logs, &customLog)
				operatorFound = true

				break
			}
		}

		if !operatorFound {
			newOperator := loglist3.Operator{
				Name: additionalLog.Operator,
				Logs: []*loglist3.Log{&customLog},
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
