package web

import (
	"fmt"
	"testing"
)

func newTestClient(id, connectionIP, connectionPort, realIP, userAgent string) *client {
	c := &client{
		clientData: clientData{
			connectionIP:     connectionIP,
			connectionPort:   connectionPort,
			realIPFromHeader: realIP,
			userAgent:        userAgent,
		},
		id: id,
	}
	return c
}

// TestClientName tests if the Name() function returns properly formatted names based on various client configurations.
func TestClientName(t *testing.T) {
	tests := []struct {
		name           string
		id             string
		connectionIP   string
		connectionPort string
		realIP         string
		userAgent      string
		want           string
	}{
		{
			name:           "connection IP only",
			id:             "M7hBCSxj",
			connectionIP:   "1.2.3.4",
			connectionPort: "1234",
			realIP:         "",
			userAgent:      "",
			want:           "[M7hBCSxj] - 1.2.3.4:1234",
		},
		{
			name:           "realIP same as connectionIP",
			id:             "Epdy7ZIl",
			connectionIP:   "1.2.3.4",
			connectionPort: "1234",
			realIP:         "1.2.3.4",
			userAgent:      "",
			want:           "[Epdy7ZIl] - 1.2.3.4:1234",
		},
		{
			name:           "realIP differs from connectionIP",
			id:             "4Y0NE9v0",
			connectionIP:   "10.0.0.1",
			connectionPort: "1234",
			realIP:         "203.0.113.5",
			userAgent:      "",
			want:           "[4Y0NE9v0] - 10.0.0.1:1234 (via 203.0.113.5)",
		},
		{
			name:           "with user agent",
			id:             "a32J8PW4",
			connectionIP:   "1.2.3.4",
			connectionPort: "1234",
			realIP:         "",
			userAgent:      "go-certstream/1.0",
			want:           "[a32J8PW4] - 1.2.3.4:1234 - 'go-certstream/1.0'",
		},
		{
			name:           "with user agent and proxy",
			id:             "qiBSXENv",
			connectionIP:   "10.0.0.1",
			connectionPort: "1234",
			realIP:         "203.0.113.5",
			userAgent:      "go-certstream/1.0",
			want:           "[qiBSXENv] - 10.0.0.1:1234 (via 203.0.113.5) - 'go-certstream/1.0'",
		},
		{
			name:           "user agent with newline is escaped",
			id:             "enf8k2HQ",
			connectionIP:   "1.2.3.4",
			connectionPort: "1234",
			realIP:         "",
			userAgent:      "bad\nagent",
			want:           "[enf8k2HQ] - 1.2.3.4:1234 - 'bad\\nagent'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(tt.id, tt.connectionIP, tt.connectionPort, tt.realIP, tt.userAgent)
			got := c.Name()
			if got != tt.want {
				t.Errorf("Name() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGenerateClientID tests if generating a client ID produces a string of the correct length and character set.
func TestGenerateClientID(t *testing.T) {
	id := generateClientID()
	if len(id) != 8 {
		t.Errorf("generateClientID() length = %d, want 8", len(id))
	}

	for _, ch := range id {
		if !isValidIDChar(ch) {
			t.Errorf("generateClientID() contains invalid character: %q", ch)
		}
	}
}

// TestGenerateClientIDUniqueness tests if there are collisions within 1000 generated IDs.
func TestGenerateClientIDUniqueness(t *testing.T) {
	const iterations = 1000
	seen := make(map[string]struct{}, iterations)

	for i := range iterations {
		id := generateClientID()
		if _, exists := seen[id]; exists {
			t.Logf("collision after %d iterations (non-fatal, low probability expected)", i)
		}
		seen[id] = struct{}{}
	}

	if len(seen) < iterations/2 {
		t.Errorf("too many collisions: only %d unique IDs out of %d", len(seen), iterations)
	}
}

func isValidIDChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9')
}

// TestClientNameAlwaysContainsID tests if the id prefix is always present in the Name() output.
func TestClientNameAlwaysContainsID(t *testing.T) {
	c := newTestClient("TESTID1X", "5.6.7.8", "", "", "")
	got := c.Name()
	expected := fmt.Sprintf("[%s]", "TESTID1X")
	if len(got) < len(expected) || got[:len(expected)] != expected {
		t.Errorf("Name() %q does not start with id prefix %q", got, expected)
	}
}
