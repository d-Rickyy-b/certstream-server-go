package certificatetransparency

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/x509"
)

// tiledWorker processes a single tiled (Static CT API) log.
type tiledWorker struct {
	name          string
	operatorName  string
	monitoringURL string
	publicKey     crypto.PublicKey
	entryChan     chan models.Entry
	ctIndex       int64
	mu            sync.Mutex
	running       bool
	cancel        context.CancelFunc
}

// startDownloadingCerts starts downloading certificates from the tiled CT log. This method is blocking.
func (tw *tiledWorker) startDownloadingCerts(ctx context.Context) {
	ctx, tw.cancel = context.WithCancel(ctx)

	log.Printf("Initializing tiled worker for CT log: %s\n", tw.monitoringURL)
	defer log.Printf("Stopping tiled worker for CT log: %s\n", tw.monitoringURL)

	tw.mu.Lock()
	if tw.running {
		log.Printf("Tiled worker for '%s' already running\n", tw.monitoringURL)
		tw.mu.Unlock()
		return
	}

	tw.running = true
	defer func() { tw.running = false }()
	tw.mu.Unlock()

	for {
		log.Printf("Starting tiled worker for CT log: %s\n", tw.monitoringURL)
		workerErr := tw.runWorker(ctx)
		if workerErr != nil {
			if strings.Contains(workerErr.Error(), "no such host") {
				log.Printf("Tiled worker for '%s' failed to resolve host: %s\n", tw.monitoringURL, workerErr)
				return
			}
			log.Printf("Tiled worker for '%s' failed with error: %s\n", tw.monitoringURL, workerErr)
		}

		// Check if the context was cancelled
		select {
		case <-ctx.Done():
			log.Printf("Context was cancelled; Stopping tiled worker for '%s'\n", tw.monitoringURL)
			return
		default:
			log.Printf("Tiled worker for '%s' sleeping for 5 seconds due to error\n", tw.monitoringURL)
			time.Sleep(5 * time.Second)
			log.Printf("Restarting tiled worker for '%s'\n", tw.monitoringURL)
			continue
		}
	}
}

func (tw *tiledWorker) stop() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.cancel()
}

// runWorker runs a single worker for a tiled CT log. This method is blocking.
func (tw *tiledWorker) runWorker(ctx context.Context) error {
	hc := &http.Client{
		Timeout: 30 * time.Second,
	}

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: tw.monitoringURL,
		PublicKey:        tw.publicKey,
		HTTPClient:       hc,
		UserAgent:        userAgent,
		Timeout:          5 * time.Minute,
	})
	if err != nil {
		log.Printf("Error creating sunlight client: %s\n", err)
		return fmt.Errorf("failed to create sunlight client: %w", err)
	}

	// Get the current checkpoint to know the tree size
	checkpoint, _, err := client.Checkpoint(ctx)
	if err != nil {
		log.Printf("Could not get checkpoint for '%s': %s\n", tw.monitoringURL, err)
		return fmt.Errorf("failed to get checkpoint: %w", err)
	}

	treeSize := checkpoint.N

	// If recovery is not enabled, start from the current tree size
	recoveryEnabled := config.AppConfig.General.Recovery.Enabled
	if !recoveryEnabled {
		tw.ctIndex = treeSize
		log.Printf("Starting tiled log '%s' from tree size %d (skipping past entries)\n", tw.monitoringURL, tw.ctIndex)
	} else {
		log.Printf("Starting tiled log '%s' from saved index %d (tree size: %d)\n", tw.monitoringURL, tw.ctIndex, treeSize)
	}

	// Poll for new entries continuously
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Get updated checkpoint
			checkpoint, _, err := client.Checkpoint(ctx)
			if err != nil {
				log.Printf("Could not get checkpoint for '%s': %s\n", tw.monitoringURL, err)
				continue
			}

			newTreeSize := checkpoint.N
			if newTreeSize <= tw.ctIndex {
				// No new entries
				continue
			}

			log.Printf("Tiled log '%s' has new entries: %d -> %d\n", tw.monitoringURL, tw.ctIndex, newTreeSize)

			// Fetch new entries (checkpoint.Tree is already the tree we need)
			startIndex := tw.ctIndex
			for index, entry := range client.Entries(ctx, checkpoint.Tree, startIndex) {
				if entry == nil {
					continue
				}

				// Process the entry
				certstreamEntry, parseErr := tw.parseTiledEntry(entry, index)
				if parseErr != nil {
					log.Printf("Error parsing tiled entry at index %d: %s\n", index, parseErr)
					continue
				}

				// Send to entry channel
				tw.entryChan <- certstreamEntry

				// Update index
				tw.ctIndex = index + 1

				// Update metrics
				if entry.IsPrecert {
					atomic.AddInt64(&processedPrecerts, 1)
				} else {
					atomic.AddInt64(&processedCerts, 1)
				}
			}

			// Check if there was an error during iteration
			if err := client.Err(); err != nil {
				log.Printf("Error during tiled log iteration for '%s': %s\n", tw.monitoringURL, err)
				return err
			}
		}
	}
}

// parseTiledEntry converts a sunlight.LogEntry to a models.Entry.
func (tw *tiledWorker) parseTiledEntry(entry *sunlight.LogEntry, index int64) (models.Entry, error) {
	if entry == nil {
		return models.Entry{}, errors.New("tiled entry is nil")
	}

	// Parse the certificate
	var cert *x509.Certificate
	var rawData []byte
	var isPrecert bool
	var err error

	if entry.IsPrecert {
		// For precerts, entry.Certificate holds the raw TBS certificate bytes,
		// not a full DER certificate, so ParseTBSCertificate must be used.
		cert, err = x509.ParseTBSCertificate(entry.Certificate)
		if err != nil {
			return models.Entry{}, fmt.Errorf("failed to parse precert TBS certificate: %w", err)
		}
		rawData = entry.PreCertificate
		isPrecert = true
	} else {
		cert, err = x509.ParseCertificate(entry.Certificate)
		if err != nil {
			return models.Entry{}, fmt.Errorf("failed to parse certificate: %w", err)
		}
		rawData = entry.Certificate
		isPrecert = false
	}

	data, err := tw.buildDataFromCert(cert, index, isPrecert, rawData)
	if err != nil {
		return models.Entry{}, err
	}

	certstreamEntry := models.Entry{
		Data:        data,
		MessageType: "certificate_update",
	}
	if isPrecert {
		certstreamEntry.Data.UpdateType = "PrecertLogEntry"
	} else {
		certstreamEntry.Data.UpdateType = "X509LogEntry"
	}

	return certstreamEntry, nil
}

// buildDataFromCert creates a models.Data structure from an x509 certificate.
func (tw *tiledWorker) buildDataFromCert(cert *x509.Certificate, index int64, isPrecert bool, rawData []byte) (models.Data, error) {
	// Build cert link (note: tiled logs don't have the same get-entries endpoint, so we just use the monitoring URL)
	certLink := fmt.Sprintf("%s (index: %d)", tw.monitoringURL, index)

	// Create main data structure
	data := models.Data{
		CertIndex: uint64(index),
		CertLink:  certLink,
		Seen:      float64(time.Now().UnixMilli()) / 1_000,
		Source: models.Source{
			Name:          tw.name,
			URL:           tw.monitoringURL,
			Operator:      tw.operatorName,
			NormalizedURL: normalizeCtlogURL(tw.monitoringURL),
		},
	}

	// Convert certificate to LeafCert
	data.LeafCert = leafCertFromX509cert(*cert)

	// If it's a precert, recalculate hashes and set poison byte
	if isPrecert {
		calculatedHash := calculateSHA1(rawData)
		data.LeafCert.Fingerprint = calculatedHash
		data.LeafCert.SHA1 = calculatedHash
		data.LeafCert.SHA256 = calculateSHA256(rawData)
		data.LeafCert.Extensions.CTLPoisonByte = true
	}

	// Set AsDER
	certAsDER := base64.StdEncoding.EncodeToString(rawData)
	data.LeafCert.AsDER = certAsDER

	// Note: Chain parsing is not available for tiled logs in the same way
	// The ChainFingerprints field exists but we'd need to fetch the actual certs
	data.Chain = []models.LeafCert{}

	return data, nil
}
