package web

import (
	"net/http"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certstream"
)

var exampleCert certstream.Entry

// exampleFull handles requests to the /full-stream/example.json endpoint.
// It returns a JSON representation of the full example certificate.
func exampleFull(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(exampleCert.JSON()) //nolint:errcheck
}

// exampleLite handles requests to the /example.json endpoint.
// It returns a JSON representation of the lite example certificate.
func exampleLite(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(exampleCert.JSONLite()) //nolint:errcheck
}

// exampleDomains handles requests to the /domains-only/example.json endpoint.
// It returns a JSON representation of the domain data.
func exampleDomains(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(exampleCert.JSONDomains()) //nolint:errcheck
}

func SetExampleCert(cert certstream.Entry) {
	exampleCert = cert
}
