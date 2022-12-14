package prometheus

import (
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"certstream-server-go/internal/certificatetransparency"
	"certstream-server-go/internal/web"

	"github.com/VictoriaMetrics/metrics"
)

var (
	ctLogMetricsInitialized = false
	ctLogMetricsInitMutex   = &sync.Mutex{}

	tempCertMetricsLastRefreshed = time.Time{}
	tempCertMetrics              = certificatetransparency.CTMetrics{}

	// Number of currently connected clients.
	fullClientCount = metrics.NewGauge("certstreamservergo_clients_total{type=\"full\"}", func() float64 {
		return float64(web.ClientHandler.ClientFullCount())
	})
	liteClientCount = metrics.NewGauge("certstreamservergo_clients_total{type=\"lite\"}", func() float64 {
		return float64(web.ClientHandler.ClientLiteCount())
	})
	domainClientCount = metrics.NewGauge("certstreamservergo_clients_total{type=\"domain\"}", func() float64 {
		return float64(web.ClientHandler.ClientDomainsCount())
	})

	// Number of certificates processed by the CT watcher.
	processedCertificates = metrics.NewGauge("certstreamservergo_certificates_total{type=\"regular\"}", func() float64 {
		return float64(certificatetransparency.GetProcessedCerts())
	})
	processedPreCertificates = metrics.NewGauge("certstreamservergo_certificates_total{type=\"precert\"}", func() float64 {
		return float64(certificatetransparency.GetProcessedPrecerts())
	})
)

// WritePrometheus provides an easy way to write metrics to a writer.
func WritePrometheus(w io.Writer, exposeProcessMetrics bool) {
	ctLogMetricsInitMutex.Lock()
	if !ctLogMetricsInitialized {
		initCtLogMetrics()
	}
	ctLogMetricsInitMutex.Unlock()
	metrics.WritePrometheus(w, exposeProcessMetrics)
}

// For having metrics regarding each individual CT log, we need to register them manually.
// initCtLogMetrics fetches all the CT Logs and registers one metric per log.
func initCtLogMetrics() {
	logs := certificatetransparency.GetLogOperators()
	// logs := certificatetransparency.GetLogs()

	for operator, urls := range logs {
		operator := operator // Copy variable to new scope
		for i := 0; i < len(urls); i++ {
			url := urls[i]
			name := fmt.Sprintf("certstreamservergo_certs_by_log_total{url=\"%s\",operator=\"%s\"}", url, operator)
			metrics.NewGauge(name, func() float64 {
				return float64(getCertCountForLog(operator, url))
			})
		}
	}

	if len(logs) > 0 {
		ctLogMetricsInitialized = true
	}
}

// getCertCountForLog returns the number of certificates processed from a specific CT log.
// It caches the result for 5 seconds. Subsequent calls to this method will return the cached result.
func getCertCountForLog(operatorName, logname string) int64 {
	// Add some caching to avoid having to lock the mutex every time
	if time.Since(tempCertMetricsLastRefreshed) > time.Second*5 {
		log.Println("Refreshing tempCertMetrics")
		tempCertMetricsLastRefreshed = time.Now()
		tempCertMetrics = certificatetransparency.GetCertMetrics()
	}

	return tempCertMetrics[operatorName][logname]
}
