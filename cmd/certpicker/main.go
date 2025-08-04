package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
)

var userAgent = fmt.Sprintf("Certstream v%s (github.com/d-Rickyy-b/certstream-server-go)", config.Version)

func main() {
	ctLogFlag := flag.String("log", "", "URL of the CT log - e.g. ct.googleapis.com/logs/eu1/xenon2025h2")
	certIDFlag := flag.Int64("cert", 0, "ID of the certificate to fetch from the CT log")
	chainFlag := flag.Bool("chain", false, "Include full chain for the certificate")
	asDERFlag := flag.Bool("asder", false, "Include DER encoding of the certificate")
	flag.Parse()

	ctLog := *ctLogFlag
	certID := *certIDFlag

	if ctLog == "" {
		log.Fatalln("CT log URL is required")
	}
	if !strings.HasPrefix(ctLog, "https://") {
		ctLog = "https://" + ctLog
	}

	// Initialize the http client and json client provided by the ct library
	hc := http.Client{Timeout: 30 * time.Second}
	jsonClient, e := client.New(ctLog, &hc, jsonclient.Options{UserAgent: userAgent})
	if e != nil {
		log.Fatalln("Error creating JSON client:", e)
	}

	// Get entries from CT log
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entries, getEntriesErr := jsonClient.GetRawEntries(c, certID, certID)
	if getEntriesErr != nil {
		log.Fatalln("Error getting entries from CT log: ", getEntriesErr)
	}

	// Loop over entries and pars each one.
	for _, leafEntry := range entries.Entries {
		rawLogEntry, err := ct.RawLogEntryFromLeaf(certID, &leafEntry)
		if err != nil {
			log.Fatalln("Error creating raw log entry: ", err)
		}

		entry, parseErr := certificatetransparency.ParseCertstreamEntry(rawLogEntry, "N/A", "N/A", ctLog)
		if parseErr != nil {
			log.Fatalln("Error parsing certstream entry: ", parseErr)
		}

		// Check if the entry is a certificate or precertificate
		if logEntry, toLogEntryErr := rawLogEntry.ToLogEntry(); toLogEntryErr != nil {
			log.Println("Error converting rawLogEntry to logEntry: ", toLogEntryErr)
		} else {
			matcher := scanner.MatchAll{}
			if logEntry.X509Cert != nil && matcher.CertificateMatches(logEntry.X509Cert) {
				entry.Data.UpdateType = "X509LogEntry"
			}
			if logEntry.Precert != nil && matcher.PrecertificateMatches(logEntry.Precert) {
				entry.Data.UpdateType = "PrecertLogEntry"
			}
		}

		// Remove DER encoding and chain if not requested
		if !*asDERFlag {
			entry.Data.LeafCert.AsDER = ""
			for i := range entry.Data.Chain {
				entry.Data.Chain[i].AsDER = ""
			}
		}

		// Remove chain if not requested
		if !*chainFlag {
			entry.Data.Chain = nil
		}

		// Marshal the certificate entry to JSON and pretty print it
		result, marshalErr := json.MarshalIndent(entry, "", "  ")
		if marshalErr != nil {
			return
		}

		fmt.Println(string(result))
	}
}
