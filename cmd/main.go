package main

import (
	"flag"
	"go-certstream-server/internal/certificatetransparency"
	"go-certstream-server/internal/web"
	"log"
)

// main is the entry point for the application.
func main() {
	// var configFile = flag.String("config", "config.yml", "Path to config file")
	var port = flag.Int("port", 8080, "port to listen on")
	var networkIf = flag.String("interface", "127.0.0.1", "interface to listen on")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	go web.StartServer(*networkIf, *port)

	watcher := certificatetransparency.Watcher{}
	watcher.Start()
}
