package main

import (
	"flag"
	"log"

	"certstream-server-go/internal/certificatetransparency"
	"certstream-server-go/internal/config"
	"certstream-server-go/internal/prometheus"
	"certstream-server-go/internal/web"
)

// main is the entry point for the application.
func main() {
	// var configFile = flag.String("config", "config.yml", "Path to config file")
	configFile := flag.String("config", "config.yaml", "path to the config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	conf, err := config.ReadConfig(*configFile)
	if err != nil {
		log.Fatalln("Error while parsing yaml file:", err)
	}

	webserver := web.NewWebsocketServer(conf.Webserver.ListenAddr, conf.Webserver.ListenPort, conf.Webserver.CertPath, conf.Webserver.CertKeyPath)

	if conf.Prometheus.Enabled {
		// If prometheus is enabled, and interface is either unconfigured or same as webserver config, use existing webserver
		if (conf.Prometheus.ListenAddr == "" || conf.Prometheus.ListenAddr == conf.Webserver.ListenAddr) &&
			(conf.Prometheus.ListenPort == 0 || conf.Prometheus.ListenPort == conf.Webserver.ListenPort) {
			log.Println("Starting prometheus server on same interface as webserver")
			webserver.RegisterPrometheus(conf.Prometheus.MetricsURL, prometheus.WritePrometheus)
		} else {
			log.Println("Starting prometheus server on new interface")
			metricsServer := web.NewMetricsServer(conf.Prometheus.ListenAddr, conf.Prometheus.ListenPort, conf.Webserver.CertPath, conf.Webserver.CertKeyPath)
			metricsServer.RegisterPrometheus(conf.Prometheus.MetricsURL, prometheus.WritePrometheus)
			go metricsServer.Start()
		}
	}

	go webserver.Start()

	watcher := certificatetransparency.Watcher{}
	watcher.Start()
}
