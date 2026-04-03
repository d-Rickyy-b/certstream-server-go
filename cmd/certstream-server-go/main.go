package main

import (
	"log"
)

// main is the entry point for the application.
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	Execute()
}
