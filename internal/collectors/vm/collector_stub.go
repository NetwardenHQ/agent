//go:build !linux
// +build !linux

package vm

import (
	"context"
	"log/slog"
	"netwarden/internal/config"
	"netwarden/internal/metrics"
)

// Collector is a stub implementation for non-Linux platforms.
type Collector struct {
	hostname string
	logger   *slog.Logger
}

// CollectorOption configures the VM collector.
type CollectorOption func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) CollectorOption {
	return func(c *Collector) {
		c.logger = logger
	}
}

// NewCollector creates a new VM collector (stub for non-Linux platforms).
func NewCollector(cfg config.VMConfig, hostname string, opts ...CollectorOption) *Collector {
	collector := &Collector{
		hostname: hostname,
		logger:   slog.Default().With("component", "vm_collector_stub"),
	}

	for _, opt := range opts {
		opt(collector)
	}

	collector.logger.Debug("VM collector not supported on this platform")
	return collector
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "vm_stub"
}

// Enabled returns false as VM monitoring is not supported on non-Linux platforms.
func (c *Collector) Enabled() bool {
	return false
}

// Collect returns empty metrics as VM monitoring is not supported.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	return []metrics.Metric{}, nil
}

// HealthCheck always returns nil for stub implementation.
func (c *Collector) HealthCheck(ctx context.Context) error {
	return nil
}

// Close is a no-op for stub implementation.
func (c *Collector) Close() error {
	return nil
}
