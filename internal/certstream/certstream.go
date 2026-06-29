package certstream

// The certstream package provides the main entry point for the certstream-server-go application.
// It initializes the webserver and the watcher for the certificate transparency logs.
// It also handles signals for graceful shutdown of the server.

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/logger"
	"github.com/d-Rickyy-b/certstream-server-go/internal/metrics"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

type Certstream struct {
	webserver     *web.Server
	metricsServer *web.Server
	watcher       *certificatetransparency.Watcher
	config        config.Config
}

func NewRawCertstream(config config.Config) *Certstream {
	cs := Certstream{}
	cs.config = config

	return &cs
}

// NewCertstreamServer creates a new Certstream server from a config struct.
func NewCertstreamServer(config config.Config) (*Certstream, error) {
	cs := NewRawCertstream(config)

	// Initialize the webserver used for the websocket server
	webserver := web.NewWebsocketServer(
		config.Webserver.ListenAddr,
		config.Webserver.ListenPort,
		config.Webserver.CertPath,
		config.Webserver.CertKeyPath,
	)
	cs.webserver = webserver
	cs.watcher = certificatetransparency.NewWatcher()

	// Setup metrics server
	cs.setupMetrics(webserver)

	return cs, nil
}

// NewCertstreamFromConfigFile creates a new Certstream server from a config file.
func NewCertstreamFromConfigFile(configPath string) (*Certstream, error) {
	conf, err := config.ReadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	return NewCertstreamServer(conf)
}

// setupMetrics configures the webserver to handle prometheus metrics according to the config.
func (cs *Certstream) setupMetrics(webserver *web.Server) {
	if cs.config.Prometheus.Enabled {
		// If prometheus is enabled, and interface is either unconfigured or same as webserver config, use existing webserver
		if (cs.config.Prometheus.ListenAddr == "" || cs.config.Prometheus.ListenAddr == cs.config.Webserver.ListenAddr) &&
			(cs.config.Prometheus.ListenPort == 0 || cs.config.Prometheus.ListenPort == cs.config.Webserver.ListenPort) {
			slog.Info("Starting prometheus server on same interface as webserver")
			webserver.RegisterPrometheus(cs.config.Prometheus.MetricsURL, metrics.Prometheus.Write)
		} else {
			slog.Info("Starting prometheus server on new interface")

			cs.metricsServer = web.NewMetricsServer(
				cs.config.Prometheus.ListenAddr,
				cs.config.Prometheus.ListenPort,
				cs.config.Prometheus.CertPath,
				cs.config.Prometheus.CertKeyPath,
			)
			cs.metricsServer.RegisterPrometheus(cs.config.Prometheus.MetricsURL, metrics.Prometheus.Write)
		}
	}
}

// Start starts the webserver and the watcher.
// This is a blocking function that will run until the server is stopped.
func (cs *Certstream) Start() {
	slog.Info("Starting certstream-server-go", "version", config.Version)

	// handle signals in a separate goroutine
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go signalHandler(signals, cs.Stop)

	// If there is no watcher initialized, create a new one
	if cs.watcher == nil {
		cs.watcher = certificatetransparency.NewWatcher()
	}

	// Start webserver and metrics server
	if cs.webserver == nil {
		logger.Fatal("Webserver not initialized, exiting")
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

// CreateIndexFile creates the index file for the certificate transparency logs.
// It gets only called when the CLI flag --create-index-file is set.
func (cs *Certstream) CreateIndexFile(outFile string) error {
	// If there is no watcher initialized, create a new one
	if cs.watcher == nil {
		cs.watcher = certificatetransparency.NewWatcher()
	}

	err := cs.watcher.CreateIndexFile(outFile)
	if err != nil {
		return fmt.Errorf("error creating index file: %w", err)
	}

	return nil
}

// signalHandler listens for signals in order to gracefully shut down the server.
// Executes the callback function when a signal is received.
func signalHandler(signals chan os.Signal, callback func()) {
	slog.Info("Listening for signals...")

	sig := <-signals
	slog.Info("Received signal, shutting down", "signal", sig)
	callback()
	os.Exit(0)
}
