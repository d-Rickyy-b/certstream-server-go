package certificatetransparency

import "sync"

type (
	// OperatorLogs is a map of operator names to a list of CT log urls, operated by said operator.
	OperatorLogs map[string][]string
	// OperatorMetric is a map of CT log urls to the number of certs processed by said log.
	OperatorMetric map[string]int64
	// CTMetrics is a map of operator names to a map of CT log urls to the number of certs processed by said log.
	CTMetrics map[string]OperatorMetric
)

var (
	processedCerts    int64
	processedPrecerts int64
	metrics           = LogMetrics{metrics: make(CTMetrics)}
)

// LogMetrics is a struct that holds a map of metrics for each CT log grouped by operator.
// Metrics can be accessed and written concurrently through the Get, Set and Inc methods.
type LogMetrics struct {
	mutex   sync.RWMutex
	metrics CTMetrics
}

// GetCTMetrics returns a copy of the internal metrics map.
func (m *LogMetrics) GetCTMetrics() CTMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	copiedMap := make(CTMetrics)

	for operator, urls := range m.metrics {
		copiedMap[operator] = make(OperatorMetric)
		for url, count := range urls {
			copiedMap[operator][url] = count
		}
	}

	return copiedMap
}

// OperatorLogMapping returns a map of operator names to a list of CT logs.
func (m *LogMetrics) OperatorLogMapping() OperatorLogs {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	logOperators := make(map[string][]string, len(m.metrics))

	for operator, urls := range m.metrics {
		urlList := make([]string, len(urls))
		counter := 0

		for url := range urls {
			urlList[counter] = url
			counter++
		}
		logOperators[operator] = urlList
	}

	return logOperators
}

// Get the metric for a given operator and ct url.
func (m *LogMetrics) Get(operator, url string) int64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	return m.metrics[operator][url]
}

// Set the metric for a given operator and ct url.
func (m *LogMetrics) Set(operator, url string, value int64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	m.metrics[operator][url] = value
}

// Inc the metric for a given operator and ct url.
func (m *LogMetrics) Inc(operator, url string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	m.metrics[operator][url]++
}

func GetProcessedCerts() int64 {
	return processedCerts
}

func GetProcessedPrecerts() int64 {
	return processedPrecerts
}

func GetCertMetrics() CTMetrics {
	return metrics.GetCTMetrics()
}

func GetLogOperators() map[string][]string {
	return metrics.OperatorLogMapping()
}
