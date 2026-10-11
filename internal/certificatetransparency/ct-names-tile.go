package certificatetransparency

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// NamesEntry is a single entry of a names tile.
// See https://github.com/FiloSottile/sunlight/blob/main/names-tiles.md
type NamesEntry struct {
	// Timestamp in milliseconds.
	Timestamp int64 `json:"Timestamp"`
	Subject   struct {
		CommonName string `json:"CommonName"`
	} `json:"Subject"`
	DNS []string `json:"DNS"`
	IP  []string `json:"IP"`
}

// ParseNamesTile parses a names tile into NamesEntry values.
func ParseNamesTile(data []byte) ([]NamesEntry, error) {
	var entries []NamesEntry

	for line := range bytes.Lines(data) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var entry NamesEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidNamesTile, err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
