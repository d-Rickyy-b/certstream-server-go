package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certstream"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
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

	cs, err := certstream.NewCertstreamFromConfigFile(*configFile)
	if err != nil {
		log.Fatalf("Error while creating certstream server: %v", err)
	}

	cs.Start()
}
