package certificatetransparency

import (
	"errors"
	"testing"

	"github.com/google/certificate-transparency-go/loglist3"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

var emptyLogList = loglist3.LogList{}

// buildLogList is a helper that constructs a loglist3.LogList from simple operator/log specs.
func buildLogList(operators []struct {
	name      string
	logs      []string
	tiledLogs []string
},
) loglist3.LogList {
	ll := loglist3.LogList{}

	for _, op := range operators {
		operator := &loglist3.Operator{Name: op.name}

		for _, u := range op.logs {
			u := u
			operator.Logs = append(operator.Logs, &loglist3.Log{URL: u})
		}

		for _, u := range op.tiledLogs {
			u := u
			operator.TiledLogs = append(operator.TiledLogs, &loglist3.TiledLog{MonitoringURL: u})
		}

		ll.Operators = append(ll.Operators, operator)
	}

	return ll
}

// newMockListFetcher returns a function that returns the passed loglist
func newMockListFetcher(t *testing.T, loglist loglist3.LogList, err error) LogListFetcher {
	t.Helper()

	return func() (loglist3.LogList, error) {
		return loglist, err
	}
}

// countLogs returns the total number of classic (non-tiled) logs across all operators.
func countLogs(ll loglist3.LogList) int {
	n := 0
	for _, op := range ll.Operators {
		n += len(op.Logs)
	}

	return n
}

// countTiledLogs returns the total number of tiled logs across all operators.
func countTiledLogs(ll loglist3.LogList) int {
	n := 0
	for _, op := range ll.Operators {
		n += len(op.TiledLogs)
	}

	return n
}

// findLog searches for a log URL in the LogList. Returns true if found.
func findLog(ll loglist3.LogList, url string) bool {
	for _, op := range ll.Operators {
		for _, l := range op.Logs {
			if l.URL == url {
				return true
			}
		}
	}

	return false
}

// findTiledLog searches for a tiled log MonitoringURL in the LogList. Returns true if found.
func findTiledLog(ll loglist3.LogList, monitoringURL string) bool {
	for _, op := range ll.Operators {
		for _, tl := range op.TiledLogs {
			if tl.MonitoringURL == monitoringURL {
				return true
			}
		}
	}

	return false
}

// findOperator returns the operator with the given name, or nil if not found.
func findOperator(ll loglist3.LogList, name string) *loglist3.Operator {
	for _, op := range ll.Operators {
		if op.Name == name {
			return op
		}
	}

	return nil
}

// --- Tests for default log enable/disable ---

// TestGetAllLogs_DefaultLogsEnabled verifies that when DisableDefaultLogs is false
// the logs returned by the mock fetcher appear in the result.
func TestGetAllLogs_DefaultLogsEnabled(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	mockList := buildLogList([]struct {
		name      string
		logs      []string
		tiledLogs []string
	}{
		{"Google", []string{"ct.googleapis.com/logs/xenon2024/"}, nil},
		{"Cloudflare", []string{"ct.cloudflare.com/logs/nimbus2024/"}, nil},
	})

	logListFetcher := newMockListFetcher(t, mockList, nil)
	config.AppConfig.General.DisableDefaultLogs = false

	result, err := getAllLogs(logListFetcher)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if countLogs(result) != 2 {
		t.Errorf("expected 2 default logs, got %d", countLogs(result))
	}

	if !findLog(result, "ct.googleapis.com/logs/xenon2024/") {
		t.Error("expected Google log to be present")
	}

	if !findLog(result, "ct.cloudflare.com/logs/nimbus2024/") {
		t.Error("expected Cloudflare log to be present")
	}
}

// TestGetAllLogs_DefaultLogsDisabled verifies that when DisableDefaultLogs is true
// no default logs are fetched and the result only contains custom logs.
func TestGetAllLogs_DefaultLogsDisabled(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	mockList := buildLogList([]struct {
		name      string
		logs      []string
		tiledLogs []string
	}{
		{"Google", []string{"ct.googleapis.com/logs/xenon2024/"}, nil},
	})

	config.AppConfig.General.DisableDefaultLogs = true

	result, err := getAllLogs(newMockListFetcher(t, mockList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The mock fetcher should NOT have been called; result should have no default logs.
	if countLogs(result) != 0 {
		t.Errorf("expected 0 logs when default logs are disabled, got %d", countLogs(result))
	}

	if len(result.Operators) != 0 {
		t.Errorf("expected 0 operators when default logs are disabled, got %d", len(result.Operators))
	}
}

// TestGetAllLogs_FetcherError verifies that an error from the fetcher is propagated correctly.
func TestGetAllLogs_FetcherError(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	config.AppConfig.General.DisableDefaultLogs = false

	_, err := getAllLogs(newMockListFetcher(t, emptyLogList, errors.New("network error")))
	if err == nil {
		t.Fatal("expected error when fetcher fails, got nil")
	}
}

// --- Tests for additional classic logs ---

// TestGetAllLogs_AdditionalLog_NewOperator verifies that an additional log whose operator
// does not yet exist in the list creates a new operator entry.
func TestGetAllLogs_AdditionalLog_NewOperator(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	config.AppConfig.General.DisableDefaultLogs = true
	config.AppConfig.General.AdditionalLogs = []config.LogConfig{
		{Operator: "CustomOp", URL: "custom.example.com/log1/", Description: "Custom Log 1"},
	}

	result, err := getAllLogs(newMockListFetcher(t, emptyLogList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op := findOperator(result, "CustomOp")
	if op == nil {
		t.Fatal("expected operator 'CustomOp' to be created")
	}

	if len(op.Logs) != 1 {
		t.Errorf("expected 1 log for 'CustomOp', got %d", len(op.Logs))
	}

	if op.Logs[0].URL != "custom.example.com/log1/" {
		t.Errorf("unexpected log URL: %s", op.Logs[0].URL)
	}
}

// TestGetAllLogs_AdditionalLog_ExistingOperator verifies that an additional log is appended
// to an already-existing operator.
func TestGetAllLogs_AdditionalLog_ExistingOperator(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	mockList := buildLogList([]struct {
		name      string
		logs      []string
		tiledLogs []string
	}{
		{"Google", []string{"ct.googleapis.com/logs/xenon2024/"}, nil},
	})

	config.AppConfig.General.DisableDefaultLogs = false
	config.AppConfig.General.AdditionalLogs = []config.LogConfig{
		{Operator: "Google", URL: "ct.googleapis.com/logs/custom/", Description: "Custom Google Log"},
	}

	result, err := getAllLogs(newMockListFetcher(t, mockList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op := findOperator(result, "Google")
	if op == nil {
		t.Fatal("expected operator 'Google' to be present")
	}

	if len(op.Logs) != 2 {
		t.Errorf("expected 2 logs for 'Google', got %d", len(op.Logs))
	}

	if !findLog(result, "ct.googleapis.com/logs/custom/") {
		t.Error("expected custom Google log to be present")
	}
}

// TestGetAllLogs_AdditionalLog_NoDuplicate verifies that adding a log that already exists
// (same URL) does not create a duplicate entry.
func TestGetAllLogs_AdditionalLog_NoDuplicate(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	existingURL := "ct.googleapis.com/logs/xenon2024/"
	mockList := buildLogList([]struct {
		name      string
		logs      []string
		tiledLogs []string
	}{
		{"Google", []string{existingURL}, nil},
	})

	config.AppConfig.General.DisableDefaultLogs = false
	config.AppConfig.General.AdditionalLogs = []config.LogConfig{
		{Operator: "Google", URL: existingURL, Description: "Duplicate"},
	}

	result, err := getAllLogs(newMockListFetcher(t, mockList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op := findOperator(result, "Google")
	if op == nil {
		t.Fatal("expected operator 'Google' to be present")
	}

	if len(op.Logs) != 1 {
		t.Errorf("expected 1 log (no duplicate), got %d", len(op.Logs))
	}
}

// TestGetAllLogs_MultipleAdditionalLogs verifies that multiple additional logs across
// different operators are all added correctly.
func TestGetAllLogs_MultipleAdditionalLogs(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	config.AppConfig.General.DisableDefaultLogs = true
	config.AppConfig.General.AdditionalLogs = []config.LogConfig{
		{Operator: "OperatorA", URL: "loga.example.com/log1/", Description: "Log A1"},
		{Operator: "OperatorA", URL: "loga.example.com/log2/", Description: "Log A2"},
		{Operator: "OperatorB", URL: "logb.example.com/log1/", Description: "Log B1"},
	}

	result, err := getAllLogs(newMockListFetcher(t, emptyLogList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if countLogs(result) != 3 {
		t.Errorf("expected 3 logs total, got %d", countLogs(result))
	}

	opA := findOperator(result, "OperatorA")
	if opA == nil || len(opA.Logs) != 2 {
		t.Errorf("expected 2 logs for 'OperatorA', got %v", opA)
	}

	opB := findOperator(result, "OperatorB")
	if opB == nil || len(opB.Logs) != 1 {
		t.Errorf("expected 1 log for 'OperatorB', got %v", opB)
	}
}

// --- Tests for additional tiled logs ---

// TestGetAllLogs_AdditionalTiledLog_NewOperator verifies that an additional tiled log
// whose operator does not yet exist creates a new operator entry.
func TestGetAllLogs_AdditionalTiledLog_NewOperator(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	config.AppConfig.General.DisableDefaultLogs = true
	config.AppConfig.General.AdditionalTiledLogs = []config.LogConfig{
		{Operator: "TiledOp", URL: "tiled.example.com/log1/", Description: "Tiled Log 1"},
	}

	result, err := getAllLogs(newMockListFetcher(t, emptyLogList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op := findOperator(result, "TiledOp")
	if op == nil {
		t.Fatal("expected operator 'TiledOp' to be created")
	}

	if len(op.TiledLogs) != 1 {
		t.Errorf("expected 1 tiled log for 'TiledOp', got %d", len(op.TiledLogs))
	}

	if op.TiledLogs[0].MonitoringURL != "tiled.example.com/log1/" {
		t.Errorf("unexpected tiled log URL: %s", op.TiledLogs[0].MonitoringURL)
	}
}

// TestGetAllLogs_AdditionalTiledLog_ExistingOperator verifies that an additional tiled log
// is appended to an already-existing operator.
func TestGetAllLogs_AdditionalTiledLog_ExistingOperator(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	mockList := buildLogList([]struct {
		name      string
		logs      []string
		tiledLogs []string
	}{
		{"Google", nil, []string{"tiled.googleapis.com/logs/existing/"}},
	})

	config.AppConfig.General.DisableDefaultLogs = false
	config.AppConfig.General.AdditionalTiledLogs = []config.LogConfig{
		{Operator: "Google", URL: "tiled.googleapis.com/logs/custom/", Description: "Custom Tiled"},
	}

	result, err := getAllLogs(newMockListFetcher(t, mockList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op := findOperator(result, "Google")
	if op == nil {
		t.Fatal("expected operator 'Google' to be present")
	}

	if len(op.TiledLogs) != 2 {
		t.Errorf("expected 2 tiled logs for 'Google', got %d", len(op.TiledLogs))
	}

	if !findTiledLog(result, "tiled.googleapis.com/logs/custom/") {
		t.Error("expected custom tiled log to be present")
	}
}

// TestGetAllLogs_AdditionalTiledLog_NoDuplicate verifies that adding a tiled log that
// already exists does not create a duplicate entry.
func TestGetAllLogs_AdditionalTiledLog_NoDuplicate(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	existingURL := "tiled.googleapis.com/logs/existing/"
	mockList := buildLogList([]struct {
		name      string
		logs      []string
		tiledLogs []string
	}{
		{"Google", nil, []string{existingURL}},
	})

	config.AppConfig.General.DisableDefaultLogs = false
	config.AppConfig.General.AdditionalTiledLogs = []config.LogConfig{
		{Operator: "Google", URL: existingURL, Description: "Duplicate Tiled"},
	}

	result, err := getAllLogs(newMockListFetcher(t, mockList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op := findOperator(result, "Google")
	if op == nil {
		t.Fatal("expected operator 'Google' to be present")
	}

	if len(op.TiledLogs) != 1 {
		t.Errorf("expected 1 tiled log (no duplicate), got %d", len(op.TiledLogs))
	}
}

// TestGetAllLogs_MixedAdditionalLogs verifies that a combination of classic and tiled
// additional logs are both added correctly when default logs are disabled.
func TestGetAllLogs_MixedAdditionalLogs(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig = config.Config{}
	})

	config.AppConfig.General.DisableDefaultLogs = true
	config.AppConfig.General.AdditionalLogs = []config.LogConfig{
		{Operator: "MixedOp", URL: "classic.example.com/log/", Description: "Classic Log"},
	}
	config.AppConfig.General.AdditionalTiledLogs = []config.LogConfig{
		{Operator: "MixedOp", URL: "tiled.example.com/log/", Description: "Tiled Log"},
	}

	result, err := getAllLogs(newMockListFetcher(t, emptyLogList, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if countLogs(result) != 1 {
		t.Errorf("expected 1 classic log, got %d", countLogs(result))
	}

	if countTiledLogs(result) != 1 {
		t.Errorf("expected 1 tiled log, got %d", countTiledLogs(result))
	}

	op := findOperator(result, "MixedOp")
	if op == nil {
		t.Fatal("expected operator 'MixedOp' to be present")
	}

	if len(op.Logs) != 1 || len(op.TiledLogs) != 1 {
		t.Errorf("MixedOp: expected 1 classic + 1 tiled, got %d classic, %d tiled", len(op.Logs), len(op.TiledLogs))
	}
}
