package certificatetransparency

type Entry struct {
	Data        Data   `json:"data"`
	MessageType string `json:"message_type"`
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
	Name string `json:"name"`
	URL  string `json:"url"`
}

type LeafCert struct {
	AllDomains         []string   `json:"all_domains,omitempty"`
	AsDER              string     `json:"as_der,omitempty"`
	Extensions         Extensions `json:"extensions"`
	Fingerprint        string     `json:"fingerprint"`
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
	EmailAddress *string `json:"email_address"`
	Aggregated   *string `json:"aggregated"`
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
