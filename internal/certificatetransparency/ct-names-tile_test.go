package certificatetransparency

import (
	"errors"
	"slices"
	"testing"
)

const namesTileJSONL = `{"Timestamp":1753375092043,"Subject":{"CommonName":"example.com"},"DNS":["example.com","www.example.com"]}
{"Timestamp":1753375092044,"Subject":{"Organization":["Example Inc"]},"DNS":["mail.example.org"],"IP":["192.0.2.1"]}
`

func TestParseNamesTile(t *testing.T) {
	entries, err := ParseNamesTile([]byte(namesTileJSONL))
	if err != nil {
		t.Fatalf("ParseNamesTile: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	if entries[0].Timestamp != 1753375092043 || entries[0].Subject.CommonName != "example.com" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}

	if !slices.Equal(entries[0].DNS, []string{"example.com", "www.example.com"}) {
		t.Errorf("DNS = %v", entries[0].DNS)
	}

	if !slices.Equal(entries[1].IP, []string{"192.0.2.1"}) {
		t.Errorf("IP = %v", entries[1].IP)
	}
}

func TestParseNamesTile_Invalid(t *testing.T) {
	if _, err := ParseNamesTile([]byte("{not json}\n")); !errors.Is(err, ErrInvalidNamesTile) {
		t.Errorf("want ErrInvalidNamesTile, got %v", err)
	}
}

func TestParseNamesEntry(t *testing.T) {
	var namesEntry NamesEntry
	namesEntry.Timestamp = 1753375092043
	namesEntry.Subject.CommonName = "example.com"
	namesEntry.DNS = []string{"www.example.com", "example.com"}

	entry := ParseNamesEntry(namesEntry, 42, "operator", "log", "https://ct.example.com/log/")

	if !entry.DomainsOnly {
		t.Error("entry should be marked as domains only")
	}

	if entry.Data.CertIndex != 42 {
		t.Errorf("CertIndex = %d, want 42", entry.Data.CertIndex)
	}

	// The common name is already in the SANs and must not be added twice.
	if !slices.Equal(entry.Data.LeafCert.AllDomains, []string{"www.example.com", "example.com"}) {
		t.Errorf("AllDomains = %v", entry.Data.LeafCert.AllDomains)
	}

	if entry.Data.Source.Timestamp != 1753375092.043 {
		t.Errorf("Source.Timestamp = %f", entry.Data.Source.Timestamp)
	}
}
