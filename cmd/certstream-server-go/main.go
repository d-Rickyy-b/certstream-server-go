package main

import (
	"github.com/d-Rickyy-b/certstream-server-go/internal/logger"
)

// main is the entry point for the application.
func main() {
	logger.Init()
	Execute()
}
