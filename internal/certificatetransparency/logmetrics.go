package certificatetransparency

import (
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"os"
	"sync"
	"time"
)

type (
	// OperatorLogs is a map of operator names to a list of CT log urls, operated by said operator.
	OperatorLogs map[string][]string
	// OperatorMetric is a map of CT log urls to the number of certs processed by said log.
	OperatorMetric map[string]int64
	// CTMetrics is a map of operator names to a map of CT log urls to the number of certs processed by said log.
	CTMetrics map[string]OperatorMetric
	// CTCertIndex is a map of CT log urls to the last processed certficate index on the said log.
	CTCertIndex map[string]uint64
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
func (m *LogMetrics) Inc(operator, url string, index uint64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	m.metrics[operator][url]++

	m.index[url] = index
}

// GetAllCTIndexes returns a copy of the internal CT index map.
func (m *LogMetrics) GetAllCTIndexes() CTCertIndex {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// make a copy of the index and return it, since map is a reference type
	copyOfIndex := make(CTCertIndex)
	maps.Copy(copyOfIndex, m.index)

	return copyOfIndex
}

// GetCTIndex returns the last cert index processed for a given CT url.
func (m *LogMetrics) GetCTIndex(url string) uint64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	index, ok := m.index[url]
	if !ok {
		return 0
	}

	return index
}

// SetCTIndex sets the index for a given CT url.
func (m *LogMetrics) SetCTIndex(url string, index uint64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	log.Println("Setting CT index for ", url, " to ", index)
	m.index[url] = index
}

// LoadCTIndex loads the last cert index processed for each CT url if it exists.
func (m *LogMetrics) LoadCTIndex(ctIndexFilePath string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	bytes, readErr := os.ReadFile(ctIndexFilePath)
	if readErr != nil {
		// Create the file if it doesn't exist
		if os.IsNotExist(readErr) {
			err := createCTIndexFile(ctIndexFilePath, m)
			if err != nil {
				log.Printf("Error creating CT index file: '%s'\n", ctIndexFilePath)
				log.Panicln(err)
			}
		} else {
			// If the file exists but we can't read it, log the error and panic
			log.Panicln(readErr)
		}
	}

	jerr := json.Unmarshal(bytes, &m.index)
	if jerr != nil {
		log.Printf("Error unmarshalling CT index file: '%s'\n", ctIndexFilePath)
		log.Panicln(jerr)
	}

	log.Println("Successfully loaded saved CT indexes")
}

func createCTIndexFile(ctIndexFilePath string, m *LogMetrics) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	log.Printf("Specified CT index file does not exist: '%s'\n", ctIndexFilePath)
	log.Println("Creating CT index file now!")

	file, createErr := os.Create(ctIndexFilePath)
	if createErr != nil {
		log.Printf("Error creating CT index file: '%s'\n", ctIndexFilePath)
		log.Panicln(createErr)
	}

	bytes, marshalErr := json.Marshal(m.index)
	if marshalErr != nil {
		return marshalErr
	}
	_, writeErr := file.Write(bytes)
	if writeErr != nil {
		log.Printf("Error writing to CT index file: '%s'\n", ctIndexFilePath)
		log.Panicln(writeErr)
	}
	file.Close()

	return nil
}

// SaveCertIndexesAtInterval saves the index of CTLogs at given intervals.
// We first create a temp file and write the index data to it. Only then do we move the temp file to the actual
// permanent index file. This prevents the last good index file from being clobbered if the program was shutdown/killed
// in-between the write operation.
func (m *LogMetrics) SaveCertIndexesAtInterval(interval time.Duration, ctIndexFilePath string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		m.SaveCertIndexes(ctIndexFilePath)
	}
}

// SaveCertIndexes saves the index of CTLogs to a file.
func (m *LogMetrics) SaveCertIndexes(ctIndexFilePath string) {
	tempFilePath := fmt.Sprintf("%s.tmp", ctIndexFilePath)

	// Get the index data
	ctIndex := m.GetAllCTIndexes()
	bytes, cerr := json.MarshalIndent(ctIndex, "", " ")
	if cerr != nil {
		log.Panic(cerr)
	}

	// Save data to a temporary file first
	file, openErr := os.OpenFile(tempFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if openErr != nil {
		log.Println("Could not save CT index to temporary file: ", openErr)
		return
	}

	truncateErr := file.Truncate(0)
	if truncateErr != nil {
		log.Println("Error truncating CT index temp file: ", truncateErr)
		return
	}
	// TODO: check for short writes
	_, writeErr := file.Write(bytes)
	if writeErr != nil {
		log.Println("Error writing to CT index temp file: ", writeErr)
		return
	}
	syncErr := file.Sync()
	if syncErr != nil {
		log.Println("Error syncing CT index temp file: ", syncErr)
		return
	}

	file.Close()

	// Atomically move the temp file to the permanent file
	renameErr := os.Rename(tempFilePath, ctIndexFilePath)
	if renameErr != nil {
		log.Println("Error renaming CT index temp file: ", renameErr)
		return
	}
}

// GetProcessedCerts returns the total number of processed certificates.
func GetProcessedCerts() int64 {
	return processedCerts
}

// GetProcessedPrecerts returns the total number of processed precertificates.
func GetProcessedPrecerts() int64 {
	return processedPrecerts
}

func GetCertMetrics() CTMetrics {
	return metrics.GetCTMetrics()
}

func GetLogOperators() map[string][]string {
	return metrics.OperatorLogMapping()
}
