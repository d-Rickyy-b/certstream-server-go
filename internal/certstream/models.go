package certstream

import (
	"bytes"
	"encoding/json"
	"log"
)

type Entry struct {
	Data           Data   `json:"data"`
	MessageType    string `json:"message_type"`
	cachedJSON     []byte
	cachedJSONLite []byte
}

// Clone returns a new copy of the Entry.
func (e *Entry) Clone() Entry {
	return Entry{
		Data:           e.Data,
		MessageType:    e.MessageType,
		cachedJSON:     e.cachedJSON,
		cachedJSONLite: e.cachedJSONLite,
	}
}

// JSON returns the json encoded Entry as byte slice and caches it for later access.
func (e *Entry) JSON() []byte {
	if len(e.cachedJSON) > 0 {
		return e.cachedJSON
	}
	e.cachedJSON = e.entryToJSONBytes()

	return e.cachedJSON
}

// JSONNoCache returns the json encoded Entry as byte slice without caching it.
func (e *Entry) JSONNoCache() []byte {
	return e.entryToJSONBytes()
}

// JSONLite does the same as JSON() but removes the chain and cert's DER representation.
func (e *Entry) JSONLite() []byte {
	if len(e.cachedJSONLite) > 0 {
		return e.cachedJSONLite
	}
	e.cachedJSONLite = e.JSONLiteNoCache()

	return e.cachedJSONLite
}

// JSONLiteNoCache does the same as JSONNoCache() but removes the chain and cert's DER representation.
func (e *Entry) JSONLiteNoCache() []byte {
	newEntry := e.Clone()
	newEntry.Data.Chain = nil
	newEntry.Data.LeafCert.AsDER = ""

	return newEntry.entryToJSONBytes()
}

// JSONDomains returns the json encoded domains (DomainsEntry) as byte slice.
func (e *Entry) JSONDomains() []byte {
	domainsEntry := DomainsEntry{
		Data:        e.Data.LeafCert.AllDomains,
		MessageType: "dns_entries",
	}

	domainsEntryBytes, err := json.Marshal(domainsEntry)
	if err != nil {
		log.Println(err)
	}

	return domainsEntryBytes
}

// entryToJSONBytes encodes an Entry to a JSON byte slice.
func (e *Entry) entryToJSONBytes() []byte {
	buf := bytes.Buffer{}
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	err := enc.Encode(e)
	if err != nil {
		log.Println(err)
	}

	return buf.Bytes()
}

type Data struct {
	CertIndex  int64      `json:"cert_index"`
	CertLink   string     `json:"cert_link"`
	Chain      []LeafCert `json:"chain,omitempty"`
	LeafCert   LeafCert   `json:"leaf_cert"`
	Seen       float64    `json:"seen"`
	Source     Source     `json:"source"`
	UpdateType string     `json:"update_type"`
}

type Source struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	Operator      string `json:"-"`
	NormalizedURL string `json:"-"`
}

type LeafCert struct {
	AllDomains         []string   `json:"all_domains"`
	AsDER              string     `json:"as_der,omitempty"`
	Extensions         Extensions `json:"extensions"`
	Fingerprint        string     `json:"fingerprint"`
	SHA1               string     `json:"sha1"`
	SHA256             string     `json:"sha256"`
	NotAfter           int64      `json:"not_after"`
	NotBefore          int64      `json:"not_before"`
	SerialNumber       string     `json:"serial_number"`
	SignatureAlgorithm string     `json:"signature_algorithm"`
	Subject            Subject    `json:"subject"`
	Issuer             Subject    `json:"issuer"`
	IsCA               bool       `json:"is_ca"`
}

type Subject struct {
	C            *string `json:"C"`
	CN           *string `json:"CN"`
	L            *string `json:"L"`
	O            *string `json:"O"`
	OU           *string `json:"OU"`
	ST           *string `json:"ST"`
	Aggregated   *string `json:"aggregated"`
	EmailAddress *string `json:"email_address"`
}

type Extensions struct {
	AuthorityInfoAccess           *string `json:"authorityInfoAccess,omitempty"`
	AuthorityKeyIdentifier        *string `json:"authorityKeyIdentifier,omitempty"`
	BasicConstraints              *string `json:"basicConstraints,omitempty"`
	CertificatePolicies           *string `json:"certificatePolicies,omitempty"`
	CtlSignedCertificateTimestamp *string `json:"ctlSignedCertificateTimestamp,omitempty"`
	ExtendedKeyUsage              *string `json:"extendedKeyUsage,omitempty"`
	KeyUsage                      *string `json:"keyUsage,omitempty"`
	SubjectAltName                *string `json:"subjectAltName,omitempty"`
	SubjectKeyIdentifier          *string `json:"subjectKeyIdentifier,omitempty"`
	CTLPoisonByte                 bool    `json:"ctlPoisonByte,omitempty"`
}

type DomainsEntry struct {
	Data        []string `json:"data"`
	MessageType string   `json:"message_type"`
}
