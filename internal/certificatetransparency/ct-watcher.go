package certificatetransparency

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/trillian/client/backoff"

	"github.com/d-Rickyy-b/certstream-server-go/internal/broadcast"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/metrics"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/scanner"
)

var UserAgent = fmt.Sprintf("Certstream Server v%s (github.com/d-Rickyy-b/certstream-server-go)", config.Version)

// Watcher is a central component within certstream-server-go. It manages the workers for all the monitored ct logs.
// It keeps track of all the monitored logs and periodically checks for new logs that aren't monitored yet.
type Watcher struct {
	workers    []*worker
	workersMu  sync.RWMutex
	wg         sync.WaitGroup
	context    context.Context
	certChan   chan models.Entry
	cancelFunc context.CancelFunc
}

// NewWatcher creates a new Watcher.
func NewWatcher() *Watcher {
	certChan := make(chan models.Entry, 5000)

	return &Watcher{
		certChan: certChan,
	}
}

// NewWatcherWithChannel creates a new Watcher and initializes it with the provided cert channel.
func NewWatcherWithChannel(certChan chan models.Entry) *Watcher {
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

		// Load saved CT indexes from provided index file
		metrics.Metrics.LoadCTIndex(ctIndexFilePath)

		// Start background job to save CTIndexes at regular intervals
		storageInterval := time.Second * 30
		go metrics.Metrics.SaveCertIndexesAtInterval(w.context, storageInterval, ctIndexFilePath)
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

// watchNewLogs is a blocking method that continuously monitors the Google log list for new logs and starts
// a worker for each new log found. It can be stopped by cancelling the watcher's context (e.g. via Stop()).
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

// updateLogs checks the Google log list for new logs once and adds new workers for those to the watcher.
func (w *Watcher) updateLogs() {
	// Get a list of urls of all CT logs provided by Google
	logList, err := getAllLogs(googleLogListFetcher)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Checking for new ct logs...")

	// Track all URLs that should be monitored after reconciliation.
	monitoredURLs := make(map[string]struct{})
	newCTs := 0

	w.workersMu.Lock()
	defer w.workersMu.Unlock()

	for _, operator := range logList.Operators {
		// Classic logs
		for _, transparencyLog := range operator.Logs {
			url := transparencyLog.URL
			desc := transparencyLog.Description
			normURL := normalizeCtlogURL(url)

			if transparencyLog.State.LogStatus() == loglist3.RetiredLogStatus {
				log.Printf("Skipping retired CT log: %s\n", normURL)
				continue
			}

			monitoredURLs[normURL] = struct{}{}

			if w.addLogIfNew(operator.Name, desc, url, false) {
				newCTs++
			}
		}

		// Tiled logs
		for _, transparencyLog := range operator.TiledLogs {
			url := transparencyLog.MonitoringURL
			desc := transparencyLog.Description
			normURL := normalizeCtlogURL(url)

			if transparencyLog.State.LogStatus() == loglist3.RetiredLogStatus {
				log.Printf("Skipping retired CT log: %s\n", normURL)
				continue
			}

			monitoredURLs[normURL] = struct{}{}

			if w.addLogIfNew(operator.Name, desc, url, true) {
				newCTs++
			}
		}
	}

	log.Printf("New ct logs found: %d\n", newCTs)

	// Optionally stop workers for logs not in the monitoredURLs set
	if *config.AppConfig.General.DropOldLogs {
		removed := 0

		for _, ctWorker := range w.workers {
			normURL := normalizeCtlogURL(ctWorker.ctURL)
			if _, ok := monitoredURLs[normURL]; !ok {
				log.Printf("Stopping worker. CT URL not found in LogList or retired: '%s'\n", ctWorker.ctURL)
				ctWorker.stop()

				removed++
			}
		}

		log.Printf("Removed ct logs: %d\n", removed)
	}

	log.Printf("Currently monitored ct logs: %d\n", len(w.workers))
}

// addLogIfNew checks if a log is already being watched and adds it if not.
// Returns true if a new log was added, false otherwise.
func (w *Watcher) addLogIfNew(operatorName, description, url string, isTiled bool) bool {
	normURL := normalizeCtlogURL(url)

	// Check if the log is already being watched
	for _, ctWorker := range w.workers {
		workerURL := normalizeCtlogURL(ctWorker.ctURL)
		if workerURL == normURL {
			return false
		}
	}

	// Log is not being watched yet, so add it
	w.wg.Add(1)

	lastCTIndex := metrics.Metrics.GetCTIndex(normURL)
	ctWorker := worker{
		name:         description,
		operatorName: operatorName,
		ctURL:        url,
		entryChan:    w.certChan,
		ctIndex:      lastCTIndex,
		isTiled:      isTiled,
	}
	w.workers = append(w.workers, &ctWorker)

	metrics.Metrics.Init(operatorName, normURL)

	// Start a goroutine for each worker
	go func() {
		defer w.wg.Done()

		ctWorker.startDownloadingCerts(w.context)
		w.discardWorker(&ctWorker)
	}()

	return true
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

// Stop stops the watcher.
func (w *Watcher) Stop() {
	log.Printf("Stopping watcher\n")

	if config.AppConfig.General.Recovery.Enabled {
		// Store current CT Indexes before shutting down
		filePath := config.AppConfig.General.Recovery.CTIndexFile

		err := metrics.Metrics.SaveCertIndexes(filePath)
		if err != nil {
			log.Printf("Failed to save CT index file: %v\n", err)
		}
	}

	w.cancelFunc()
}

// CreateIndexFile creates a ct_index.json file based on the current STHs of all available logs.
func (w *Watcher) CreateIndexFile(filePath string) error {
	logs, err := getAllLogs(googleLogListFetcher)
	if err != nil {
		return err
	}

	httpClient := newHTTPClient()
	w.context, w.cancelFunc = context.WithCancel(context.Background())

	log.Println("Fetching current STH for all logs...")

	for _, operator := range logs.Operators {
		// Iterate over each log of the operator
		for _, transparencyLog := range operator.Logs {
			if transparencyLog.State.LogStatus() == loglist3.RetiredLogStatus {
				log.Printf("Skipping retired CT log: %s\n", transparencyLog.URL)
				continue
			}

			normalizedURL := normalizeCtlogURL(transparencyLog.URL)
			metrics.Metrics.Init(operator.Name, normalizedURL)
			log.Println("Fetching STH for", normalizedURL)

			jsonClient, e := client.New(transparencyLog.URL, httpClient, jsonclient.Options{UserAgent: UserAgent})
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

			metrics.Metrics.SetCTIndex(normalizedURL, sth.TreeSize)
		}

		for _, transparencyLog := range operator.TiledLogs {
			if transparencyLog.State.LogStatus() == loglist3.RetiredLogStatus {
				log.Printf("Skipping retired CT log: %s\n", transparencyLog.MonitoringURL)
				continue
			}

			normalizedURL := normalizeCtlogURL(transparencyLog.MonitoringURL)
			metrics.Metrics.Init(operator.Name, normalizedURL)
			log.Println("Fetching checkpoint for", normalizedURL)

			staticCTClient := NewStaticCTClient(transparencyLog.MonitoringURL, httpClient, UserAgent, 0)

			checkpoint, fetchErr := staticCTClient.FetchCheckpoint(w.context)
			if fetchErr != nil {
				log.Printf("Could not get checkpoint for '%s': %s\n", transparencyLog.MonitoringURL, fetchErr)
				return ErrFetchingSTHFailed
			}

			metrics.Metrics.SetCTIndex(normalizedURL, checkpoint.Size)
		}
	}

	w.cancelFunc()

	saveErr := metrics.Metrics.SaveCertIndexes(filePath)
	if saveErr != nil {
		return fmt.Errorf("failed to save cert index: %w", saveErr)
	}

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
	isTiled      bool
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

		var workerErr error
		if w.isTiled {
			workerErr = w.runTiledWorker(ctx)
		} else {
			workerErr = w.runStandardWorker(ctx)
		}

		if workerErr != nil {
			switch {
			case errors.Is(workerErr, ErrFetchingSTHFailed):
				log.Printf("Worker for '%s' failed - could not fetch STH\n", w.ctURL)
				return
			case errors.Is(workerErr, ErrCreatingClient):
				log.Printf("Worker for '%s' failed - could not create client\n", w.ctURL)
				return
			case strings.Contains(workerErr.Error(), "no such host"):
				log.Printf("Worker for '%s' failed to resolve host: %s\n", w.ctURL, workerErr)
				return
			case errors.Is(workerErr, context.Canceled):
				log.Printf("Worker for '%s' canceled\n", w.ctURL)
				return
			}

			log.Printf("Worker for '%s' failed with unexpected error: %s\n", w.ctURL, workerErr)
		}

		// Check if the context was canceled
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

// runStandardWorker runs the worker for a single standard CT log. This method is blocking.
func (w *worker) runStandardWorker(ctx context.Context) error {
	jsonClient, e := client.New(w.ctURL, newHTTPClient(), jsonclient.Options{UserAgent: UserAgent})
	if e != nil {
		log.Printf("Error creating JSON client: %s\n", e)
		return ErrCreatingClient
	}

	// If recovery is enabled, we start at the saved index. Otherwise, we start at the latest STH.
	recoveryEnabled := config.AppConfig.General.Recovery.Enabled
	if !recoveryEnabled {
		sth, getSTHerr := jsonClient.GetSTH(ctx)
		if getSTHerr != nil {
			// TODO this can happen due to a 429 error. We should retry the request
			log.Printf("Could not get STH for '%s': %s\n", w.ctURL, getSTHerr)
			return ErrFetchingSTHFailed
		}
		// Start at the latest STH to skip all the past certificates
		w.ctIndex = sth.TreeSize
	}

	// Handle gosec G115 warning
	if w.ctIndex > math.MaxInt64 {
		log.Printf("index (%d) exceeds math.MaxInt64, skipping\n", w.ctIndex)
		return nil
	}

	certScanner := scanner.NewScanner(jsonClient, scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     256,
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
		return fmt.Errorf("error scanning for certificates: %w", scanErr)
	}

	log.Printf("Exiting worker %s without error!\n", w.ctURL)

	return nil
}

// runTiledWorker runs the worker for a single tiled CT log. This method is blocking.
func (w *worker) runTiledWorker(ctx context.Context) error {
	httpClient := newHTTPClient()

	staticCTClient := NewStaticCTClient(w.ctURL, httpClient, UserAgent, w.ctIndex)

	// If recovery is enabled and the CT index is set, we start at the saved index. Otherwise, we start at the latest checkpoint.
	validSavedCTIndexExists := config.AppConfig.General.Recovery.Enabled
	if !validSavedCTIndexExists {
		checkpoint, err := staticCTClient.FetchCheckpoint(ctx)
		if err != nil {
			log.Printf("Could not get checkpoint for '%s': %s\n", w.ctURL, err)
			return ErrFetchingSTHFailed
		}
		// Start at the latest checkpoint to skip all the past certificates
		staticCTClient.ctIndex = checkpoint.Size
	}

	err := staticCTClient.Monitor(ctx, w.foundCertCallback, w.foundPrecertCallback)
	if err != nil {
		return fmt.Errorf("error scanning for certificates: %w", err)
	}

	return nil
}

// foundCertCallback is the callback that handles cases where new regular certs are found.
func (w *worker) foundCertCallback(rawEntry *ct.RawLogEntry) {
	logType := models.SourceIsRFC6962
	if w.isTiled {
		logType = models.SourceIsTiled
	}

	entry, parseErr := ParseCertstreamEntry(rawEntry, w.operatorName, w.name, w.ctURL, logType)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}

	entry.Data.UpdateType = "X509LogEntry"
	w.entryChan <- entry

	atomic.AddInt64(&metrics.ProcessedCerts, 1)
}

// foundPrecertCallback is the callback that handles cases where new precerts are found.
func (w *worker) foundPrecertCallback(rawEntry *ct.RawLogEntry) {
	logType := models.SourceIsRFC6962
	if w.isTiled {
		logType = models.SourceIsTiled
	}

	entry, parseErr := ParseCertstreamEntry(rawEntry, w.operatorName, w.name, w.ctURL, logType)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}

	entry.Data.UpdateType = "PrecertLogEntry"
	w.entryChan <- entry

	atomic.AddInt64(&metrics.ProcessedPrecerts, 1)
}

// certHandler takes the entries out of the entryChan channel and broadcasts them to all clients.
// Only a single instance of the certHandler runs per certstream server.
func certHandler(entryChan chan models.Entry) {
	var processed uint64

	for {
		entry := <-entryChan
		processed++

		if processed%1000 == 0 {
			log.Printf("Processed %d entries | Queue length: %d\n", processed, len(entryChan))
			// Every thousandth entry, we store one certificate as example
			web.SetExampleCert(entry)
		}

		// Run JSON encoding in the background and send the result to the clients.
		broadcast.ClientHandler.MessageQueue <- entry

		// Update metrics
		url := entry.Data.Source.NormalizedURL
		operator := entry.Data.Source.Operator
		index := entry.Data.CertIndex

		metrics.Metrics.Inc(operator, url, index)
	}
}

// newHTTPClient creates a new http.Client with reasonable timeouts and connection settings for interacting with CT logs.
func newHTTPClient() *http.Client {
	httpClient := http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	return &httpClient
}
