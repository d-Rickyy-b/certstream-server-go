package config

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

var (
	// AppConfig holds the parsed configuration.
	AppConfig Config
	Version   = "1.9.0"

	ErrInvalidConfig = errors.New("invalid configuration")
	URLPathRegex     = regexp.MustCompile(`^(/[a-zA-Z0-9\-._]+)+$`)
	URLRegex         = regexp.MustCompile(`^https?://[a-zA-Z0-9\-._]+(:[0-9]+)?(/[a-zA-Z0-9\-._]+)*/?$`)
)

type Config struct {
	Webserver        Webserver
	Prometheus       Prometheus
	StreamProcessing []StreamProcessor `mapstructure:"stream_processing"`
	General          General
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

	// Check webserver config
	if !config.Webserver.Valid() {
		return false
	}

	if !config.Prometheus.Valid() {
		return false
	}

	for _, processor := range config.StreamProcessing {
		if !processor.Valid() {
			return false
		}
	}

	if !config.General.Valid() {
		return false
	}

	return true
}
