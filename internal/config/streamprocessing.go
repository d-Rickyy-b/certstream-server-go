package config

import (
	"log"
	"net"
)

type StreamProcessorType string

const (
	StreamProcessorTypeKafka StreamProcessorType = "kafka"
	StreamProcessorTypeNQS   StreamProcessorType = "nqs"
)

type StreamProcessorCompression string

const (
	StreamProcessorCompressionNone   StreamProcessorCompression = "none"
	StreamProcessorCompressionGzip   StreamProcessorCompression = "gzip"
	StreamProcessorCompressionSnappy StreamProcessorCompression = "snappy"
)

func (c StreamProcessorCompression) Valid() bool {
	switch c {
	case StreamProcessorCompressionNone, StreamProcessorCompressionGzip, StreamProcessorCompressionSnappy, "":
		return true
	default:
		return false
	}
}

type StreamProcessor struct {
	Name        string                     `mapstructure:"name"`
	Type        StreamProcessorType        `mapstructure:"type"`
	Enabled     bool                       `mapstructure:"enabled"`
	ServerAddr  string                     `mapstructure:"server_addr"`
	ServerPort  int                        `mapstructure:"server_port"`
	Topic       string                     `mapstructure:"topic"`
	Compression StreamProcessorCompression `mapstructure:"compression"`
}

func (s *StreamProcessor) Valid() bool {
	ip := net.ParseIP(s.ServerAddr)
	if ip == nil {
		log.Fatalln("Invalid IP for stream processor:", s.ServerAddr)
		return false
	}

	if s.ServerPort <= 0 {
		log.Fatalln("Invalid server port for stream processor:", s.ServerPort)
		return false
	}

	switch s.Type {
	case StreamProcessorTypeKafka, StreamProcessorTypeNQS:
	default:
		log.Fatalf("Invalid stream processor type '%s' for name '%s'\n", s.Type, s.Name)
		return false
	}

	if s.Topic == "" {
		log.Println("Found stream processing config with empty topic - using \"certstream\" as topic for name", s.Name)
		s.Topic = "certstream"
	}

	if !s.Compression.Valid() {
		log.Fatalf("Invalid compression '%s' for stream processor '%s'\n", s.Compression, s.Name)
		return false
	}

	return true
}
