package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/metrics"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

// main is the entry point for the application.
func main() {
	configFile := flag.String("config", "config.yml", "path to the config file")
	versionFlag := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("certstream-server-go v%s\n", config.Version)
		return
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting certstream-server-go v%s\n", config.Version)

	conf, err := config.ReadConfig(*configFile)
	if err != nil {
		log.Fatalln("Error while parsing yaml file:", err)
	}

	webserver := web.NewWebsocketServer(conf.Webserver.ListenAddr, conf.Webserver.ListenPort, conf.Webserver.CertPath, conf.Webserver.CertKeyPath)

	setupMetrics(conf, webserver)

	go webserver.Start()

	watcher := certificatetransparency.Watcher{}
	watcher.Start()
}

// setupMetrics configures the webserver to handle prometheus metrics according to the config.
func setupMetrics(conf config.Config, webserver *web.WebServer) {
	if conf.Prometheus.Enabled {
		// If prometheus is enabled, and interface is either unconfigured or same as webserver config, use existing webserver
		if (conf.Prometheus.ListenAddr == "" || conf.Prometheus.ListenAddr == conf.Webserver.ListenAddr) &&
			(conf.Prometheus.ListenPort == 0 || conf.Prometheus.ListenPort == conf.Webserver.ListenPort) {
			log.Println("Starting prometheus server on same interface as webserver")
			webserver.RegisterPrometheus(conf.Prometheus.MetricsURL, metrics.WritePrometheus)
		} else {
			log.Println("Starting prometheus server on new interface")
			metricsServer := web.NewMetricsServer(conf.Prometheus.ListenAddr, conf.Prometheus.ListenPort, conf.Prometheus.CertPath, conf.Prometheus.CertKeyPath)
			metricsServer.RegisterPrometheus(conf.Prometheus.MetricsURL, metrics.WritePrometheus)
			go metricsServer.Start()
		}
	}
}
