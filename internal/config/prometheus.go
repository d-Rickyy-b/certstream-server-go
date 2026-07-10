package config

import (
	"log"
	"net"
)

type Prometheus struct {
	ServerConfig `mapstructure:",squash"`

	Enabled             bool   `mapstructure:"enabled"`
	MetricsURL          string `mapstructure:"metrics_url"`
	ExposeSystemMetrics bool   `mapstructure:"expose_system_metrics"`
}

func (p *Prometheus) Valid() bool {
	if !p.Enabled {
		return true
	}

	if p.ListenAddr == "" || net.ParseIP(p.ListenAddr) == nil {
		log.Fatalln("Metrics export IP is not a valid IP")
		return false
	}

	if p.ListenPort == 0 {
		log.Fatalln("Metrics export port is not set")
		return false
	}

	if p.Whitelist == nil {
		p.Whitelist = []string{}
	}

	// Check if IPs in whitelist match pattern
	for _, ip := range p.Whitelist {
		if net.ParseIP(ip) != nil {
			continue
		}

		// Provided entry is not an IP, check if it's a CIDR range
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			log.Fatalln("Invalid IP in metrics whitelist: ", ip)
			return false
		}
	}

	for _, ip := range p.TrustedProxies {
		if net.ParseIP(ip) != nil {
			continue
		}

		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			log.Fatalln("Invalid IP/CIDR in prometheus trusted_proxies: ", ip)
			return false
		}
	}

	return true
}
