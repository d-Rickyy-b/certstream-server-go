package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateCTIndexFile_InitializesNilIndex(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: nil}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	err := m.createCTIndexFile(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if m.index == nil {
		t.Fatal("expected index to be initialized, but it is nil")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("expected file to exist, got read error: %v", readErr)
	}

	var parsed CTCertIndex
	if jsonErr := json.Unmarshal(data, &parsed); jsonErr != nil {
		t.Fatalf("expected valid JSON, got: %v", jsonErr)
	}

	if len(parsed) != 0 {
		t.Fatalf("expected empty index, got %d entries", len(parsed))
	}
}

func TestCreateCTIndexFile_WritesExistingIndexData(t *testing.T) {
	index := CTCertIndex{
		"https://ct.example.com/log": 42,
		"https://ct.other.com/log":   100,
	}
	m := &LogMetrics{metrics: make(CTMetrics), index: index}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	err := m.createCTIndexFile(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("expected file to exist, got read error: %v", readErr)
	}

	var parsed CTCertIndex
	if jsonErr := json.Unmarshal(data, &parsed); jsonErr != nil {
		t.Fatalf("expected valid JSON, got: %v", jsonErr)
	}

	for key, expectedVal := range index {
		gotVal, ok := parsed[key]
		if !ok {
			t.Errorf("expected key %q in file, but not found", key)
			continue
		}
		if gotVal != expectedVal {
			t.Errorf("for key %q: expected %d, got %d", key, expectedVal, gotVal)
		}
	}
}

func TestCreateCTIndexFile_ReturnsErrorForInvalidPath(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	// Use a path inside a non-existent directory to trigger os.Create failure.
	path := filepath.Join(t.TempDir(), "nonexistent", "ct_index.json")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid path, but did not panic")
		}
	}()

	_ = m.createCTIndexFile(path)
}

func TestLoadCTIndex_DoesNotDeadlockWhenFileMissing(t *testing.T) {
	metrics := LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	ctIndexPath := filepath.Join(t.TempDir(), "ct_index.json")
	writeErr := os.WriteFile(ctIndexPath, []byte("{}"), 0o644)
	if writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}

	done := make(chan struct{})
	go func() {
		metrics.LoadCTIndex(ctIndexPath)
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("LoadCTIndex appears to deadlock when index file is missing")
	}
}

func TestLoadCTIndex_CreatesFileWhenMissing(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	m.LoadCTIndex(path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected LoadCTIndex to create the file when missing, but file does not exist")
	}

	if len(m.index) != 0 {
		t.Fatalf("expected empty index after loading missing file, got %d entries", len(m.index))
	}
}

func TestLoadCTIndex_LoadsValidFile(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	want := CTCertIndex{
		"https://ct.example.com/log": 42,
		"https://ct.other.com/log":   999,
	}
	data, marshalErr := json.Marshal(want)
	if marshalErr != nil {
		t.Fatalf("failed to marshal test data: %v", marshalErr)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m.LoadCTIndex(path)

	for url, expectedIdx := range want {
		got := m.GetCTIndex(url)
		if got != expectedIdx {
			t.Errorf("url %q: expected index %d, got %d", url, expectedIdx, got)
		}
	}
}

func TestLoadCTIndex_LoadsEmptyJSONFile(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m.LoadCTIndex(path)

	if len(m.index) != 0 {
		t.Fatalf("expected empty index, got %d entries", len(m.index))
	}
}

func TestLoadCTIndex_LoadsEmptyFile(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic, got none")
		}
	}()

	m.LoadCTIndex(path)
}

func TestLoadCTIndex_OverwritesPreexistingIndex(t *testing.T) {
	m := &LogMetrics{
		metrics: make(CTMetrics),
		index:   CTCertIndex{"https://old.example.com/log": 1},
	}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	want := CTCertIndex{"https://new.example.com/log": 77}
	data, marshalErr := json.Marshal(want)
	if marshalErr != nil {
		t.Fatalf("failed to marshal test data: %v", marshalErr)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	m.LoadCTIndex(path)

	if got := m.GetCTIndex("https://new.example.com/log"); got != 77 {
		t.Errorf("expected new entry with index 77, got %d", got)
	}
	if got := m.GetCTIndex("https://old.example.com/log"); got != 0 {
		t.Errorf("expected old entry to be gone (0), got %d", got)
	}
}

func TestLoadCTIndex_PanicsOnInvalidJSON(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "ct_index.json")

	if err := os.WriteFile(path, []byte("not valid json"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid JSON, but did not panic")
		}
	}()

	m.LoadCTIndex(path)
}

func TestLoadCTIndex_PanicsWhenDirectoryMissing(t *testing.T) {
	m := &LogMetrics{metrics: make(CTMetrics), index: make(CTCertIndex)}
	path := filepath.Join(t.TempDir(), "nonexistent", "ct_index.json")

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when index file directory is missing, but did not panic")
		}
	}()

	m.LoadCTIndex(path)
}
