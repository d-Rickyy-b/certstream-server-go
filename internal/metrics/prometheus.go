package metrics

import (
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

var Prometheus = NewPrometheusExporter()

// PrometheusExporter is holds the metrics for the Prometheus exporter. It also provides helper functions
// to register new metrics and write the metrics data to an http response.
//
//nolint:unused
type PrometheusExporter struct {
	// Number of currently connected clients.
	fullClientCount   metrics.Gauge
	liteClientCount   metrics.Gauge
	domainClientCount metrics.Gauge

	tempCertMetricsLastRefreshed time.Time
	tempCertMetrics              CTMetrics
	tempCertMetricsMutex         sync.RWMutex

	skippedCertsCallback func() map[string]int64
}

// NewPrometheusExporter creates a new PrometheusExporter and registers the default metrics for the number of processed certificates.
func NewPrometheusExporter() *PrometheusExporter {
	exporter := &PrometheusExporter{}
	// Register metrics for the total number of certificates processed by the CT watcher.
	metrics.GetOrCreateGauge("certstreamservergo_certificates_total{type=\"regular\"}", func() float64 {
		return float64(GetProcessedCerts())
	})
	metrics.GetOrCreateGauge("certstreamservergo_certificates_total{type=\"precert\"}", func() float64 {
		return float64(GetProcessedPrecerts())
	})

	return exporter
}

// Write is a callback function that is called by a webserver in order to write metrics data to the http response.
func (pm *PrometheusExporter) Write(w io.Writer, exposeProcessMetrics bool) {
	// getSkippedCertMetrics()

	metrics.WritePrometheus(w, exposeProcessMetrics)
}

// RegisterGaugeMetric is a helper function that registers a new gauge metric with a float64 callback function.
func (pm *PrometheusExporter) RegisterGaugeMetric(label string, callback func() float64) {
	metrics.GetOrCreateGauge(label, callback)
}

// RegisterGaugeMetricInt is a helper function that registers a new gauge metric with an int64 callback function.
func (pm *PrometheusExporter) RegisterGaugeMetricInt(label string, callback func() int64) {
	metrics.GetOrCreateGauge(label, func() float64 { return float64(callback()) })
}

// RegisterClient registers a new gauge metric for the client with the given name.
func (pm *PrometheusExporter) RegisterClient(name string, callback func() float64) {
	label := fmt.Sprintf("certstreamservergo_skipped_certs{client=\"%s\"}", name)
	metrics.GetOrCreateGauge(label, callback)
}

// UnregisterClient unregisters the metric for the client with the given name.
func (pm *PrometheusExporter) UnregisterClient(name string) {
	label := fmt.Sprintf("certstreamservergo_skipped_certs{client=\"%s\"}", name)
	metrics.UnregisterMetric(label)
}

// RegisterLog registers a new gauge metric for the given CT log.
// The metric will be named "certstreamservergo_certs_by_log_total{url=\"<url>\",operator=\"<operatorName>\"}" and
// will call the given callback function to get the current value of the metric.
func (pm *PrometheusExporter) RegisterLog(operatorName, url string) {
	label := fmt.Sprintf("certstreamservergo_certs_by_log_total{url=\"%s\",operator=\"%s\"}", url, operatorName)
	metrics.GetOrCreateGauge(label, func() float64 {
		return float64(pm.getCertCountForLog(operatorName, url))
	})
}

// UnregisterMetric unregisters a metric with a given label.
func (pm *PrometheusExporter) UnregisterMetric(label string) {
	metrics.UnregisterMetric(label)
}

// getCertCountForLog returns the number of certificates processed from a specific CT log.
// It caches the result for 5 seconds. Subsequent calls to this method will return the cached result.
func (pm *PrometheusExporter) getCertCountForLog(operatorName, logname string) int64 {
	pm.tempCertMetricsMutex.Lock()
	defer pm.tempCertMetricsMutex.Unlock()

	// Add some caching to avoid having to lock the mutex every time
	if time.Since(pm.tempCertMetricsLastRefreshed) > time.Second*5 {
		pm.tempCertMetricsLastRefreshed = time.Now()
		pm.tempCertMetrics = GetCertMetrics()
	}

	operatorMetrics, ok := pm.tempCertMetrics[operatorName]
	if !ok {
		log.Printf("No metrics for operator \"%s\"", operatorName)
		return 0
	}

	count, ok := operatorMetrics[logname]
	if !ok {
		log.Printf("No metrics for log \"%s\" of operator \"%s\"", logname, operatorName)
		return 0
	}

	return count
}
