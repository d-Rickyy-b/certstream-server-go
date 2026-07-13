package config

import (
	"log"
	"net"
)

// StreamProcessorType represents the type of stream processing tool to use.
// Supported types are "kafka" and "nqs".
type StreamProcessorType string

const (
	StreamProcessorTypeKafka StreamProcessorType = "kafka"
	StreamProcessorTypeNQS   StreamProcessorType = "nqs"
)

// StreamType represents the type of stream to process.
// Supported types are "full", "lite", and "domains-only".
type StreamType string

const (
	StreamTypeFull        StreamType = "full"
	StreamTypeLite        StreamType = "lite"
	StreamTypeDomainsOnly StreamType = "domains-only"
)

// Compression represents the compression type for stream processing.
type Compression string

const (
	CompressionNone    Compression = "none"
	CompressionGzip    Compression = "gzip"
	CompressionSnappy  Compression = "snappy"
	CompressionZstd    Compression = "zstd"
	CompressionLz4     Compression = "lz4"
	CompressionDeflate Compression = "deflate"
)

func (c Compression) setDefaults() {
	if c == "" {
		c = CompressionNone
	}
}

// Valid returns true if the compression type is valid.
func (c Compression) Valid() bool {
	c.setDefaults()

	switch c {
	case CompressionNone, CompressionGzip, CompressionSnappy, CompressionZstd, CompressionLz4:
		return true
	default:
		return false
	}
}

// SupportedBy returns true if the compression type is supported by the stream processing tool.
func (c Compression) SupportedBy(t StreamProcessorType) bool {
	if c == CompressionNone {
		return true
	}

	switch t {
	case StreamProcessorTypeKafka:
		return c == CompressionNone || c == CompressionGzip || c == CompressionSnappy || c == CompressionZstd || c == CompressionLz4
	case StreamProcessorTypeNQS:
		return c == CompressionNone || c == CompressionDeflate || c == CompressionSnappy
	default:
		return false
	}
}

type StreamProcessor struct {
	Name        string              `mapstructure:"name"`
	Type        StreamProcessorType `mapstructure:"type"`
	Stream      StreamType          `mapstructure:"stream"`
	Enabled     *bool               `mapstructure:"enabled"`
	ServerAddr  string              `mapstructure:"server_addr"`
	ServerPort  int                 `mapstructure:"server_port"`
	Topic       string              `mapstructure:"topic"`
	Compression Compression         `mapstructure:"compression"`
}

func (s *StreamProcessor) setDefaults() {
	if s.Enabled == nil {
		enabled := true
		s.Enabled = &enabled
	}
	if s.Compression == "" {
		s.Compression = CompressionNone
	}
}

func (s *StreamProcessor) Valid() bool {
	s.setDefaults()
	
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

	// Check that the compression type is generally valid
	if !s.Compression.Valid() {
		log.Fatalf("Invalid compression '%s' for stream processor '%s'\n", s.Compression, s.Name)
		return false
	}

	// Check that the compression type is supported by the stream processing tool
	if !s.Compression.SupportedBy(s.Type) {
		log.Fatalf("Compression '%s' is not supported by stream processor type '%s' for name '%s'\n", s.Compression, s.Type, s.Name)
		return false
	}

	return true
}
