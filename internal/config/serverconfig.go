package config

type ServerConfig struct {
	ListenAddr     string   `mapstructure:"listen_addr"`
	ListenPort     int      `mapstructure:"listen_port"`
	CertPath       string   `mapstructure:"cert_path"`
	CertKeyPath    string   `mapstructure:"cert_key_path"`
	RealIP         bool     `mapstructure:"real_ip"`
	TrustedProxies []string `mapstructure:"trusted_proxies"`
	Whitelist      []string `mapstructure:"whitelist"`
}
