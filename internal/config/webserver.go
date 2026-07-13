package config

import (
	"log"
	"net"
)

type Webserver struct {
	ServerConfig `mapstructure:",squash"`

	FullURL            string `mapstructure:"full_url"`
	LiteURL            string `mapstructure:"lite_url"`
	DomainsOnlyURL     string `mapstructure:"domains_only_url"`
	CompressionEnabled bool   `mapstructure:"compression_enabled"`
}

func (w *Webserver) Valid() bool {
	// Still matches invalid IP addresses but good enough for detecting completely wrong formats

	if w.ListenAddr == "" || net.ParseIP(w.ListenAddr) == nil {
		log.Fatalln("Webhook listen IP is not a valid IP: ", w.ListenAddr)
		return false
	}

	if w.ListenPort == 0 {
		log.Fatalln("Webhook listen port is not set")
		return false
	}

	if w.FullURL == "" || !URLPathRegex.MatchString(w.FullURL) {
		log.Println("Webhook full URL is not set or does not match pattern '/...'")

		w.FullURL = "/full-stream"
	}

	if w.LiteURL == "" || !URLPathRegex.MatchString(w.FullURL) {
		log.Println("Webhook lite URL is not set or does not match pattern '/...'")

		w.LiteURL = "/"
	}

	if w.DomainsOnlyURL == "" || !URLPathRegex.MatchString(w.DomainsOnlyURL) {
		log.Println("Webhook domains only URL is not set or does not match pattern '/...'")

		w.FullURL = "/domains-only"
	}

	if w.FullURL == w.LiteURL {
		log.Fatalln("Webhook full URL is the same as lite URL - please fix the config!")
	}

	if w.DomainsOnlyURL == "" {
		w.FullURL = "/domains-only"
	}

	for _, ip := range w.TrustedProxies {
		if net.ParseIP(ip) != nil {
			continue
		}

		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			log.Fatalln("Invalid IP/CIDR in webserver trusted_proxies: ", ip)
			return false
		}
	}

	return true
}
