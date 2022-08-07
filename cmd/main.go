package main

import (
	"flag"
	"go-certstream-server/internal/certificatetransparency"
	"go-certstream-server/internal/config"
	"go-certstream-server/internal/web"
	"log"
)

// main is the entry point for the application.
func main() {
	// var configFile = flag.String("config", "config.yml", "Path to config file")
	var configFile = flag.String("config", "config.yaml", "path to the config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	conf, err := config.ReadConfig(*configFile)
	if err != nil {
		log.Fatalln("Error while parsing yaml file:", err)
	}

	webserver := web.NewWebsocketServer(conf.Webserver.ListenAddr, conf.Webserver.ListenPort, conf.Webserver.CertPath, conf.Webserver.CertKeyPath)
	go webserver.Start()

	watcher := certificatetransparency.Watcher{}
	watcher.Start()
}
