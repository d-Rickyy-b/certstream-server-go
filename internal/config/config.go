package config

import (
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

var (
	AppConfig Config
	Version   = "1.9.0"

	ErrInvalidConfig = errors.New("invalid configuration")
)

type ServerConfig struct {
	ListenAddr     string   `mapstructure:"listen_addr"`
	ListenPort     int      `mapstructure:"listen_port"`
	CertPath       string   `mapstructure:"cert_path"`
	CertKeyPath    string   `mapstructure:"cert_key_path"`
	RealIP         bool     `mapstructure:"real_ip"`
	TrustedProxies []string `mapstructure:"trusted_proxies"`
	Whitelist      []string `mapstructure:"whitelist"`
}

type LogConfig struct {
	Operator    string `mapstructure:"operator"`
	URL         string `mapstructure:"url"`
	Description string `mapstructure:"description"`
}

type BufferSizes struct {
	Websocket        int `mapstructure:"websocket"`
	CTLog            int `mapstructure:"ctlog"`
	BroadcastManager int `mapstructure:"broadcastmanager"`
}

type Config struct {
	Webserver struct {
		ServerConfig `mapstructure:",squash"`

		FullURL            string `mapstructure:"full_url"`
		LiteURL            string `mapstructure:"lite_url"`
		DomainsOnlyURL     string `mapstructure:"domains_only_url"`
		CompressionEnabled bool   `mapstructure:"compression_enabled"`
	}
	Prometheus struct {
		ServerConfig `mapstructure:",squash"`

		Enabled             bool   `mapstructure:"enabled"`
		MetricsURL          string `mapstructure:"metrics_url"`
		ExposeSystemMetrics bool   `mapstructure:"expose_system_metrics"`
	}
	General struct {
		// DisableDefaultLogs indicates whether the default logs used in Google Chrome and provided by Google should be disabled.
		DisableDefaultLogs bool `mapstructure:"disable_default_logs"`
		// AdditionalLogs contains additional logs provided by the user that can be used in addition to the default logs.
		AdditionalLogs      []LogConfig `mapstructure:"additional_logs"`
		AdditionalTiledLogs []LogConfig `mapstructure:"additional_tiled_logs"`
		BufferSizes         BufferSizes `mapstructure:"buffer_sizes"`
		DropOldLogs         *bool       `mapstructure:"drop_old_logs"`
		Recovery            struct {
			Enabled     bool   `mapstructure:"enabled"`
			CTIndexFile string `mapstructure:"ct_index_file"`
		} `mapstructure:"recovery"`
	}
}

// ReadConfig reads the configuration using Viper and returns a filled Config struct.
// It also validates and stores the result in AppConfig.
func ReadConfig(configPath string) (Config, error) {
	v := initViper(configPath)
	return loadConfigFromViper(v)
}

// ValidateConfig validates the config file and returns an error if the config is invalid.
func ValidateConfig(configPath string) error {
	_, parseErr := ReadConfig(configPath)
	return parseErr
}

// initViper sets up the viper instance with defaults, config file and environment variable support.
// configPath is the path to the YAML config file (e.g. "config.yaml").
// Environment variables are mapped with the prefix "CERTSTREAM" and "_" as key delimiter.
// Example: CERTSTREAM_WEBSERVER_LISTEN_PORT overrides webserver.listen_port.
func initViper(configPath string) *viper.Viper {
	v := viper.NewWithOptions(viper.KeyDelimiter("."))

	// Defaults
	v.SetDefault("webserver.listen_addr", "0.0.0.0")
	v.SetDefault("webserver.listen_port", 8080)
	v.SetDefault("webserver.full_url", "/full-stream")
	v.SetDefault("webserver.lite_url", "/")
	v.SetDefault("webserver.domains_only_url", "/domains-only")
	v.SetDefault("webserver.real_ip", false)
	v.SetDefault("webserver.trusted_proxies", []string{})
	v.SetDefault("webserver.whitelist", []string{})
	v.SetDefault("webserver.compression_enabled", false)

	v.SetDefault("prometheus.enabled", false)
	v.SetDefault("prometheus.listen_addr", "0.0.0.0")
	v.SetDefault("prometheus.listen_port", 9090)
	v.SetDefault("prometheus.metrics_url", "/metrics")
	v.SetDefault("prometheus.expose_system_metrics", false)
	v.SetDefault("prometheus.real_ip", false)
	v.SetDefault("prometheus.trusted_proxies", []string{})
	v.SetDefault("prometheus.whitelist", []string{})

	v.SetDefault("general.disable_default_logs", false)
	v.SetDefault("general.buffer_sizes.websocket", 300)
	v.SetDefault("general.buffer_sizes.ctlog", 1000)
	v.SetDefault("general.buffer_sizes.broadcastmanager", 10000)
	v.SetDefault("general.drop_old_logs", true)
	v.SetDefault("general.recovery.enabled", false)
	v.SetDefault("general.recovery.ct_index_file", "./ct_index.json")

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
		v.AddConfigPath("/app/config")
	}

	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			log.Println("No config file found, using defaults and environment variables only")
		} else {
			log.Fatalf("Error reading config file: %v", err)
		}
	} else {
		log.Printf("Using config file: %s\n", v.ConfigFileUsed())
	}

	// Environment variables
	// Prefix: CERTSTREAM  (e.g. CERTSTREAM_WEBSERVER_LISTEN_PORT)
	// Viper uses "." as key delimiter internally; environment variables use "_".
	// We replace "." with "_" when looking up env vars automatically.
	v.SetEnvPrefix("CERTSTREAM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	return v
}

// loadConfigFromViper unmarshals a viper instance into a Config struct, validates it
// and stores the result in AppConfig.
func loadConfigFromViper(v *viper.Viper) (Config, error) {
	var cfg Config

	if err := v.Unmarshal(&cfg); err != nil {
		return cfg, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if !validateConfig(&cfg) {
		return cfg, ErrInvalidConfig
	}

	AppConfig = cfg

	return cfg, nil
}

// validateConfig validates the config values and sets defaults for missing values.
func validateConfig(config *Config) bool {
	// Still matches invalid IP addresses but good enough for detecting completely wrong formats
	URLPathRegex := regexp.MustCompile(`^(/[a-zA-Z0-9\-._]+)+$`)
	URLRegex := regexp.MustCompile(`^https?://[a-zA-Z0-9\-._]+(:[0-9]+)?(/[a-zA-Z0-9\-._]+)*/?$`)

	// Check webserver config
	if config.Webserver.ListenAddr == "" || net.ParseIP(config.Webserver.ListenAddr) == nil {
		log.Fatalln("Webhook listen IP is not a valid IP: ", config.Webserver.ListenAddr)
		return false
	}

	if config.Webserver.ListenPort == 0 {
		log.Fatalln("Webhook listen port is not set")
		return false
	}

	if config.Webserver.FullURL == "" || !URLPathRegex.MatchString(config.Webserver.FullURL) {
		log.Println("Webhook full URL is not set or does not match pattern '/...'")

		config.Webserver.FullURL = "/full-stream"
	}

	if config.Webserver.LiteURL == "" || !URLPathRegex.MatchString(config.Webserver.FullURL) {
		log.Println("Webhook lite URL is not set or does not match pattern '/...'")

		config.Webserver.LiteURL = "/"
	}

	if config.Webserver.DomainsOnlyURL == "" || !URLPathRegex.MatchString(config.Webserver.DomainsOnlyURL) {
		log.Println("Webhook domains only URL is not set or does not match pattern '/...'")

		config.Webserver.FullURL = "/domains-only"
	}

	if config.Webserver.FullURL == config.Webserver.LiteURL {
		log.Fatalln("Webhook full URL is the same as lite URL - please fix the config!")
	}

	if config.Webserver.DomainsOnlyURL == "" {
		config.Webserver.FullURL = "/domains-only"
	}

	for _, ip := range config.Webserver.TrustedProxies {
		if net.ParseIP(ip) != nil {
			continue
		}

		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			log.Fatalln("Invalid IP/CIDR in webserver trusted_proxies: ", ip)
			return false
		}
	}

	//nolint:nestif
	if config.Prometheus.Enabled {
		if config.Prometheus.ListenAddr == "" || net.ParseIP(config.Prometheus.ListenAddr) == nil {
			log.Fatalln("Metrics export IP is not a valid IP")
			return false
		}

		if config.Prometheus.ListenPort == 0 {
			log.Fatalln("Metrics export port is not set")
			return false
		}

		if config.Prometheus.Whitelist == nil {
			config.Prometheus.Whitelist = []string{}
		}

		// Check if IPs in whitelist match pattern
		for _, ip := range config.Prometheus.Whitelist {
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

		for _, ip := range config.Prometheus.TrustedProxies {
			if net.ParseIP(ip) != nil {
				continue
			}

			_, _, err := net.ParseCIDR(ip)
			if err != nil {
				log.Fatalln("Invalid IP/CIDR in prometheus trusted_proxies: ", ip)
				return false
			}
		}
	}

	var validLogs, validTiledLogs []LogConfig

	if len(config.General.AdditionalLogs) > 0 {
		for _, ctLog := range config.General.AdditionalLogs {
			if !URLRegex.MatchString(ctLog.URL) {
				log.Println("Ignoring invalid additional log URL: ", ctLog.URL)
				continue
			}

			validLogs = append(validLogs, ctLog)
		}
	}

	if len(config.General.AdditionalTiledLogs) > 0 {
		for _, ctLog := range config.General.AdditionalTiledLogs {
			if !URLRegex.MatchString(ctLog.URL) {
				log.Println("Ignoring invalid additional log URL: ", ctLog.URL)
				continue
			}

			validTiledLogs = append(validTiledLogs, ctLog)
		}
	}

	config.General.AdditionalLogs = validLogs
	config.General.AdditionalTiledLogs = validTiledLogs

	if len(config.General.AdditionalLogs) == 0 && len(config.General.AdditionalTiledLogs) == 0 && config.General.DisableDefaultLogs {
		log.Fatalln("Default logs are disabled, but no additional logs are configured. Please add at least one log to the config or enable default logs.")
	}

	if config.General.BufferSizes.Websocket <= 0 {
		config.General.BufferSizes.Websocket = 300
	}

	if config.General.BufferSizes.CTLog <= 0 {
		config.General.BufferSizes.CTLog = 1000
	}

	if config.General.BufferSizes.BroadcastManager <= 0 {
		config.General.BufferSizes.BroadcastManager = 10000
	}

	// If the cleanup flag is not set, default to true
	if config.General.DropOldLogs == nil {
		log.Println("drop_old_logs is not set, defaulting to true")

		defaultCleanup := true
		config.General.DropOldLogs = &defaultCleanup
	}

	if config.General.Recovery.Enabled && config.General.Recovery.CTIndexFile == "" {
		log.Println("Recovery enabled but no index file specified. Defaulting to ./ct_index.json")

		config.General.Recovery.CTIndexFile = "./ct_index.json"
	}

	return true
}
