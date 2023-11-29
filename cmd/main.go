package main

import (
	"flag"
	"log"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certificatetransparency"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/prometheus"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"
)

// main is the entry point for the application.
func main() {
	configFile := flag.String("config", "config.yml", "path to the config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

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

func setupMetrics(conf config.Config, webserver *web.WebServer) {
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
}
