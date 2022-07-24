package certificatetransparency

import (
	"context"
	"errors"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/scanner"
	"go-certstream-server/internal/certstream"
	"go-certstream-server/internal/web"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

// Watcher describes a component that watches for new certificates in a CT log.
type Watcher struct {
	Name       string
	workers    []*worker
	cancelFunc context.CancelFunc
}

// Start starts the watcher. This method is blocking.
func (w *Watcher) Start() {
	// Get a list of urls of all CT logs
	logList, err := getAllLogs()
	if err != nil {
		log.Println(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.cancelFunc = cancel
	certChan := make(chan certstream.Entry, 5000)

	// For each CT log, create a worker and start downloading certs
	for _, transparencyLog := range logList.Logs {
		ctWorker := worker{
			name:      transparencyLog.Description,
			ctURL:     transparencyLog.URL,
			entryChan: certChan,
			context:   ctx,
		}
		w.workers = append(w.workers, &ctWorker)
		go ctWorker.startDownloadingCerts()
	}

	certHandler(certChan)
}

// Stop stops the watcher.
func (w *Watcher) Stop() {
	log.Printf("Stopping watcher '%s'\n", w.Name)
	w.cancelFunc()
}

// A worker processes a single CT log.
type worker struct {
	name      string
	ctURL     string
	context   context.Context
	entryChan chan certstream.Entry
	mu        sync.Mutex
	running   bool
}

func (w *worker) startDownloadingCerts() {
	w.mu.Lock()
	if w.running {
		log.Println("Worker already running")
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()

	// Normalize CT URL. We remove trailing slashes and prepend "https://" if it's not already there.
	w.ctURL = strings.TrimRight(w.ctURL, "/")
	if !strings.HasPrefix(w.ctURL, "https://") && !strings.HasPrefix(w.ctURL, "http://") {
		w.ctURL = "https://" + w.ctURL
	}

	jsonClient, e := client.New(w.ctURL, nil, jsonclient.Options{})
	if e != nil {
		log.Println("Error creating JSON client: ", e)
		return
	}

	sth, getSTHerr := jsonClient.GetSTH(w.context)
	if getSTHerr != nil {
		log.Println("Error retreiving STH: ", getSTHerr)
		return
	}

	certScanner := scanner.NewScanner(jsonClient, scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     10,
			ParallelFetch: 1,
			StartIndex:    int64(sth.TreeSize), // Start at the latest STH to skip all the past certificates
			Continuous:    true,
		},
		Matcher:     scanner.MatchAll{},
		PrecertOnly: false,
		NumWorkers:  1,
		BufferSize:  100,
	})

	scanErr := certScanner.Scan(w.context, w.foundCertCallback, w.foundPrecertCallback)
	if scanErr != nil {
		log.Println("Scan error: ", scanErr)
		return
	}
}

// foundCertCallback is the callback that handles cases where new regular certs are found.
func (w *worker) foundCertCallback(rawEntry *ct.RawLogEntry) {
	entry, parseErr := parseCertstreamEntry(rawEntry, w)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}
	entry.Data.UpdateType = "X509LogEntry"
	w.entryChan <- entry
}

// foundPrecertCallback is the callback that handles cases where new precerts are found.
func (w *worker) foundPrecertCallback(rawEntry *ct.RawLogEntry) {
	entry, parseErr := parseCertstreamEntry(rawEntry, w)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}
	entry.Data.UpdateType = "PrecertLogEntry"
	w.entryChan <- entry
}

// certHandler takes the entries out of the channel and broadcasts them to all clients.
func certHandler(entryChan chan certstream.Entry) {
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
	}
}

// getAllLogs returns a list of all CT logs.
func getAllLogs() (loglist.LogList, error) {
	// Download the list of all logs from ctLogInfo and decode json
	resp, err := http.Get(loglist.LogListURL)
	if err != nil {
		return loglist.LogList{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return loglist.LogList{}, errors.New("failed to download loglist")
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Panic(readErr)
	}

	allLogs, parseErr := loglist.NewFromJSON(bodyBytes)
	if parseErr != nil {
		return loglist.LogList{}, parseErr
	}
	return *allLogs, nil
}
