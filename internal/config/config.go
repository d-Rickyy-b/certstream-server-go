package config

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	AppConfig Config
	Version   = "1.8.1"
)

type ServerConfig struct {
	ListenAddr  string   `yaml:"listen_addr"`
	ListenPort  int      `yaml:"listen_port"`
	CertPath    string   `yaml:"cert_path"`
	CertKeyPath string   `yaml:"cert_key_path"`
	RealIP      bool     `yaml:"real_ip"`
	Whitelist   []string `yaml:"whitelist"`
}

type LogConfig struct {
	Operator    string `yaml:"operator"`
	URL         string `yaml:"url"`
	Description string `yaml:"description"`
}

type BufferSizes struct {
	Websocket        int `yaml:"websocket"`
	CTLog            int `yaml:"ctlog"`
	BroadcastManager int `yaml:"broadcastmanager"`
}

type Config struct {
	Webserver struct {
		ServerConfig       `yaml:",inline"`
		FullURL            string `yaml:"full_url"`
		LiteURL            string `yaml:"lite_url"`
		DomainsOnlyURL     string `yaml:"domains_only_url"`
		CompressionEnabled bool   `yaml:"compression_enabled"`
	}
	Prometheus struct {
		ServerConfig        `yaml:",inline"`
		Enabled             bool   `yaml:"enabled"`
		MetricsURL          string `yaml:"metrics_url"`
		ExposeSystemMetrics bool   `yaml:"expose_system_metrics"`
	}
	General struct {
		AdditionalLogs []LogConfig `yaml:"additional_logs"`
		BufferSizes    BufferSizes `yaml:"buffer_sizes"`
		DropOldLogs    *bool       `yaml:"drop_old_logs"`
		ResumeFromCTIndexFile bool   `yaml:"resume_from_ct_index_file"`
		CTIndexFile           string `yaml:"ct_index_file"`
	}
}

// ReadConfig reads the config file and returns a filled Config struct.
func ReadConfig(configPath string) (Config, error) {
	log.Printf("Reading config file '%s'...\n", configPath)

	conf, parseErr := parseConfigFromFile(configPath)
	if parseErr != nil {
		log.Fatalln("Error while parsing yaml file:", parseErr)
	}

	if !validateConfig(conf) {
		log.Fatalln("Invalid config")
	}
	AppConfig = *conf

	return *conf, nil
}

// parseConfigFromFile reads the config file as bytes and passes it to parseConfigFromBytes.
// It returns a filled Config struct.
func parseConfigFromFile(configFile string) (*Config, error) {
	if configFile == "" {
		configFile = "config.yml"
	}

	// Check if the file exists
	absPath, err := filepath.Abs(configFile)
	if err != nil {
		log.Printf("Couldn't convert to absolute path: '%s'\n", configFile)
		return &Config{}, err
	}

	if _, statErr := os.Stat(absPath); os.IsNotExist(statErr) {
		log.Printf("Config file '%s' does not exist\n", absPath)
		ext := filepath.Ext(absPath)
		absPath = strings.TrimSuffix(absPath, ext)

		switch ext {
		case ".yaml":
			absPath += ".yml"
		case ".yml":
			absPath += ".yaml"
		default:
			log.Printf("Config file '%s' does not have a valid extension\n", configFile)
			return &Config{}, statErr
		}

		if _, secondStatErr := os.Stat(absPath); os.IsNotExist(secondStatErr) {
			log.Printf("Config file '%s' does not exist\n", absPath)
			return &Config{}, secondStatErr
		}
	}
	log.Printf("File '%s' exists\n", absPath)

	yamlFileContent, readErr := os.ReadFile(absPath)
	if readErr != nil {
		return &Config{}, readErr
	}

	conf, parseErr := parseConfigFromBytes(yamlFileContent)
	if parseErr != nil {
		return &Config{}, parseErr
	}

	return conf, nil
}

// parseConfigFromBytes parses the config bytes and returns a filled Config struct.
func parseConfigFromBytes(data []byte) (*Config, error) {
	var config Config

	err := yaml.Unmarshal(data, &config)
	if err != nil {
		return &config, err
	}

	return &config, nil
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
			if net.ParseIP(ip) == nil {
				// Provided entry is not an IP, check if it's a CIDR range
				_, _, err := net.ParseCIDR(ip)
				if err != nil {
					log.Fatalln("Invalid IP in metrics whitelist: ", ip)
					return false
				}
			}
		}
	}

	var validLogs []LogConfig
	if len(config.General.AdditionalLogs) > 0 {
		for _, ctLog := range config.General.AdditionalLogs {
			if !URLRegex.MatchString(ctLog.URL) {
				log.Println("Ignoring invalid additional log URL: ", ctLog.URL)
				continue
			}

			validLogs = append(validLogs, ctLog)
		}
	}

	config.General.AdditionalLogs = validLogs

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

	return true
}
