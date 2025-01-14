package certificatetransparency

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

type (
	// OperatorLogs is a map of operator names to a list of CT log urls, operated by said operator.
	OperatorLogs map[string][]string
	// OperatorMetric is a map of CT log urls to the number of certs processed by said log.
	OperatorMetric map[string]int64
	// CTMetrics is a map of operator names to a map of CT log urls to the number of certs processed by said log.
	CTMetrics map[string]OperatorMetric
	// CTCertIndex is a map of CT log urls to the last processed certficate index on the said log
	CTCertIndex map[string]int64
)

var (
	processedCerts    int64
	processedPrecerts int64
	metrics           = LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
)

// LogMetrics is a struct that holds a map of metrics for each CT log grouped by operator.
// Metrics can be accessed and written concurrently through the Get, Set and Inc methods.
type LogMetrics struct {
	mutex   sync.RWMutex
	metrics CTMetrics
	index   CTCertIndex
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

// Init initializes the internal metrics map with the given operator names and CT log urls if it doesn't exist yet.
func (m *LogMetrics) Init(operator, url string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// if the operator does not exist, create a new entry
	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	// if the operator exists but the url does not, create a new entry
	if _, ok := m.metrics[operator][url]; !ok {
		m.metrics[operator][url] = 0
	}

	// if url index does not exist, create a new entry
	if _, ok := m.index[url]; !ok {
		m.index[url] = 0
	}
}

// Get the metric for a given operator and ct url.
func (m *LogMetrics) Get(operator, url string) int64 {
	// Despite this being a getter, we still need to fully lock the mutex because we might modify the map if the requested operator does not exist.
	m.mutex.Lock()
	defer m.mutex.Unlock()

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
func (m *LogMetrics) Inc(operator, url string, index int64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	m.metrics[operator][url]++

	m.index[url] = index
}

func (m *LogMetrics) GetAllCTIndexes() CTCertIndex {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.index
}

func (m *LogMetrics) GetCTIndex(url string) int64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	index, ok := m.index[url]
	if !ok {
		return 0
	}

	return index
}

// Load the last cert index that processed for each CT url if it exists
func (m *LogMetrics) LoadCTIndex(config config.Config) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	bytes, err := os.ReadFile(config.General.CTIndexFile)
	if err != nil {
		log.Println("Error while reading CTIndex file: ", err)
		return
	}

	jerr := json.Unmarshal(bytes, &m.index)
	if jerr != nil {
		log.Panicln(jerr)
	}

	log.Printf("%v", m.index)

	log.Println("Sucessfuly loaded saved CT indexes")
}

// SaveCertIndexesAtInterval saves the index of CTLogs at given intervals.
// we first create a temp file and write the index data to it, only then
// do we move the temp file to actual permanent index file, this prevents
// the last good index file from being clobbered if the program was shutdown/killed
// in-between the write operation.
func (m *LogMetrics) SaveCertIndexesAtInterval(interval time.Duration, ctIndexFileName string) {
	const tempFileName = "index.json.latest_tmp"
	if ctIndexFileName == "" {
		ctIndexFileName = "ctIndex.json"
	}

	for {
		time.Sleep(interval)

		// Get the index data
		ctIndex := m.GetAllCTIndexes()
		bytes, cerr := json.MarshalIndent(ctIndex, "", " ")
		if cerr != nil {
			log.Panic(cerr)
		}

		// Save data to a temporary file first
		file, err := os.OpenFile(tempFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Panic(err)
		}

		file.Truncate(0)
		file.Write(bytes) //TODO: check for short writes
		file.Sync()

		file.Close()

		// Atomically move the temp file to the permanent file
		os.Rename(tempFileName, ctIndexFileName)
	}
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
