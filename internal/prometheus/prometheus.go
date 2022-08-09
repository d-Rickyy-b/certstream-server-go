package prometheus

import (
	"fmt"
	"github.com/VictoriaMetrics/metrics"
	"go-certstream-server/internal/certificatetransparency"
	"go-certstream-server/internal/web"
	"io"
	"strings"
)

var (
	ctLogsInitialized = false
	fullClientCount   = metrics.NewGauge("certstreamservergo_clients_total{type=\"full\"}", func() float64 {
		return float64(web.ClientHandler.ClientFullCount())
	})
	liteClientCount = metrics.NewGauge("certstreamservergo_clients_total{type=\"lite\"}", func() float64 {
		return float64(web.ClientHandler.ClientLiteCount())
	})
	domainClientCount = metrics.NewGauge("certstreamservergo_clients_total{type=\"domain\"}", func() float64 {
		return float64(web.ClientHandler.ClientDomainsCount())
	})
	processedCertificates = metrics.NewGauge("certstreamservergo_certificates_total{type=\"regular\"}", func() float64 {
		return float64(certificatetransparency.GetProcessedCerts())
	})
	processedPreCertificates = metrics.NewGauge("certstreamservergo_certificates_total{type=\"precert\"}", func() float64 {
		return float64(certificatetransparency.GetProcessedPrecerts())
	})
)

// WritePrometheus provides an easy way to write metrics to a writer.
func WritePrometheus(w io.Writer, exposeProcessMetrics bool) {
	if !ctLogsInitialized {
		logs := certificatetransparency.GetLogs()
		for key := range logs {
			var url string
			url = strings.ReplaceAll(key, "http://", "")
			url = strings.ReplaceAll(url, "https://", "")
			url = strings.TrimSuffix(url, "/")
			metrics.NewGauge(fmt.Sprintf("certstreamservergo_certs_by_log_total{url=\"%s\"}", url), func() float64 {
				return float64(certificatetransparency.GetCertCountForLog(url))
			})
		}
		if len(logs) > 0 {
			ctLogsInitialized = true
		}
	}
	metrics.WritePrometheus(w, exposeProcessMetrics)
}
