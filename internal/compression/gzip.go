// Package compression provides data compression utilities for the Netwarden agent
// with configurable compression levels and performance metrics.
package compression

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sync"
	"time"
)

// CompressionLevel represents the gzip compression level
type CompressionLevel int

const (
	// NoCompression provides no compression
	NoCompression CompressionLevel = gzip.NoCompression
	// BestSpeed provides the fastest compression
	BestSpeed CompressionLevel = gzip.BestSpeed
	// BestCompression provides the best compression ratio
	BestCompression CompressionLevel = gzip.BestCompression
	// DefaultCompression provides a balance between speed and ratio
	DefaultCompression CompressionLevel = gzip.DefaultCompression

	// DefaultThreshold is the minimum size for compression (10KB)
	DefaultThreshold = 10240
)

// Compressor provides gzip compression with metrics
type Compressor struct {
	level     CompressionLevel
	threshold int

	// Metrics
	stats   CompressionStats
	statsMu sync.RWMutex
}

// CompressionStats tracks compression metrics
type CompressionStats struct {
	TotalCompressed   int64
	TotalUncompressed int64
	BytesSaved        int64
	CompressionCount  int64
	SkippedCount      int64
	TotalTime         time.Duration
	LastRatio         float64
}

// Config represents compressor configuration
type Config struct {
	Level     CompressionLevel
	Threshold int // Minimum size to compress (bytes)
}

// DefaultConfig returns the default compression configuration
func DefaultConfig() *Config {
	return &Config{
		Level:     DefaultCompression,
		Threshold: DefaultThreshold,
	}
}

// NewCompressor creates a new compressor with the given configuration
func NewCompressor(config *Config) (*Compressor, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Validate compression level
	if config.Level < gzip.NoCompression || config.Level > gzip.BestCompression {
		if config.Level != gzip.DefaultCompression {
			return nil, fmt.Errorf("invalid compression level: %d", config.Level)
		}
	}

	// Validate threshold
	if config.Threshold < 0 {
		return nil, fmt.Errorf("threshold cannot be negative: %d", config.Threshold)
	}

	return &Compressor{
		level:     config.Level,
		threshold: config.Threshold,
	}, nil
}

// Compress compresses data using gzip if it meets the threshold
func (c *Compressor) Compress(data []byte) (compressed []byte, wasCompressed bool, err error) {
	originalSize := len(data)

	// Skip compression for small payloads
	if originalSize < c.threshold {
		c.updateStats(func(s *CompressionStats) {
			s.SkippedCount++
		})
		return data, false, nil
	}

	start := time.Now()

	// Compress data
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, int(c.level))
	if err != nil {
		return nil, false, fmt.Errorf("failed to create gzip writer: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return nil, false, fmt.Errorf("failed to write compressed data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, false, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	compressedData := buf.Bytes()
	compressedSize := len(compressedData)
	duration := time.Since(start)

	// Calculate compression ratio
	ratio := float64(originalSize-compressedSize) / float64(originalSize) * 100

	// Update statistics
	c.updateStats(func(s *CompressionStats) {
		s.TotalCompressed += int64(compressedSize)
		s.TotalUncompressed += int64(originalSize)
		s.BytesSaved += int64(originalSize - compressedSize)
		s.CompressionCount++
		s.TotalTime += duration
		s.LastRatio = ratio
	})

	return compressedData, true, nil
}

// Decompress decompresses gzip data
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	return decompressed, nil
}

// CompressWithHeader compresses data and returns it with appropriate headers
func (c *Compressor) CompressWithHeader(data []byte) (body []byte, contentEncoding string, err error) {
	compressed, wasCompressed, err := c.Compress(data)
	if err != nil {
		return nil, "", err
	}

	if wasCompressed {
		return compressed, "gzip", nil
	}

	return data, "", nil
}

// GetStats returns current compression statistics
func (c *Compressor) GetStats() CompressionStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()
	return c.stats
}

// ResetStats resets compression statistics
func (c *Compressor) ResetStats() {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	c.stats = CompressionStats{}
}

// updateStats safely updates compression statistics
func (c *Compressor) updateStats(fn func(*CompressionStats)) {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	fn(&c.stats)
}

// GetAverageRatio returns the average compression ratio
func (c *Compressor) GetAverageRatio() float64 {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()

	if c.stats.TotalUncompressed == 0 {
		return 0
	}

	return float64(c.stats.BytesSaved) / float64(c.stats.TotalUncompressed) * 100
}

// GetAverageTime returns the average compression time
func (c *Compressor) GetAverageTime() time.Duration {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()

	if c.stats.CompressionCount == 0 {
		return 0
	}

	return c.stats.TotalTime / time.Duration(c.stats.CompressionCount)
}

// ShouldCompress determines if data should be compressed based on size
func (c *Compressor) ShouldCompress(size int) bool {
	return size >= c.threshold
}

// GetThreshold returns the compression threshold
func (c *Compressor) GetThreshold() int {
	return c.threshold
}

// GetLevel returns the compression level
func (c *Compressor) GetLevel() CompressionLevel {
	return c.level
}
