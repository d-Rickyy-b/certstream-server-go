package certstream

// The certstream package provides the main entry point for the certstream-server-go application.
// It initializes the webserver and the watcher for the certificate transparency logs.
// It also handles signals for graceful shutdown of the server.

import (
	"log"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/metrics"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

type Certstream struct {
	webserver     *web.WebServer
	metricsServer *web.WebServer
	watcher       *certificatetransparency.Watcher
	config        config.Config
}

// NewCertstreamServer creates a new Certstream server from a config struct.
func NewCertstreamServer(config config.Config) (*Certstream, error) {
	cs := Certstream{}
	cs.config = config

	// Initialize the webserver used for the websocket server
	webserver := web.NewWebsocketServer(config.Webserver.ListenAddr, config.Webserver.ListenPort, config.Webserver.CertPath, config.Webserver.CertKeyPath)
	cs.webserver = webserver

	// Setup metrics server
	cs.setupMetrics(webserver)

	return &cs, nil
}

// NewCertstreamFromConfigFile creates a new Certstream server from a config file.
func NewCertstreamFromConfigFile(configPath string) (*Certstream, error) {
	conf, err := config.ReadConfig(configPath)
	if err != nil {
		return nil, err
	}

	return NewCertstreamServer(conf)
}

// setupMetrics configures the webserver to handle prometheus metrics according to the config.
func (cs *Certstream) setupMetrics(webserver *web.WebServer) {
	if cs.config.Prometheus.Enabled {
		// If prometheus is enabled, and interface is either unconfigured or same as webserver config, use existing webserver
		if (cs.config.Prometheus.ListenAddr == "" || cs.config.Prometheus.ListenAddr == cs.config.Webserver.ListenAddr) &&
			(cs.config.Prometheus.ListenPort == 0 || cs.config.Prometheus.ListenPort == cs.config.Webserver.ListenPort) {
			log.Println("Starting prometheus server on same interface as webserver")
			webserver.RegisterPrometheus(cs.config.Prometheus.MetricsURL, metrics.WritePrometheus)
		} else {
			log.Println("Starting prometheus server on new interface")
			cs.metricsServer = web.NewMetricsServer(cs.config.Prometheus.ListenAddr, cs.config.Prometheus.ListenPort, cs.config.Prometheus.CertPath, cs.config.Prometheus.CertKeyPath)
			cs.metricsServer.RegisterPrometheus(cs.config.Prometheus.MetricsURL, metrics.WritePrometheus)
		}
	}
}

// Start starts the webserver and the watcher.
// This is a blocking function that will run until the server is stopped.
func (cs *Certstream) Start() {
	log.Printf("Starting certstream-server-go v%s\n", config.Version)

	// If there is no watcher initialized, create a new one
	if cs.watcher == nil {
		cs.watcher = &certificatetransparency.Watcher{}
	}

	// Start webserver and metrics server
	if cs.webserver == nil {
		log.Fatalln("Webserver not initialized! Exiting...")
	}
	go cs.webserver.Start()

	if cs.metricsServer != nil {
		go cs.metricsServer.Start()
	}

	// Start the watcher - this is a blocking function
	cs.watcher.Start()
}

// Stop stops the watcher and the webserver.
func (cs *Certstream) Stop() {
	if cs.watcher != nil {
		cs.watcher.Stop()
	}

	if cs.webserver != nil {
		cs.webserver.Stop()
	}

	if cs.metricsServer != nil {
		cs.metricsServer.Stop()
	}
}
