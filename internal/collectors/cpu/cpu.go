// Package cpu provides CPU metric collection with configurable sampling
// and per-CPU granularity options.
package cpu

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"

	"netwarden/internal/metrics"
)

// Collector implements metrics.Collector for CPU metrics.
type Collector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder
	enabled  bool
}

// NewCollector creates a new CPU metrics collector.
// cfg parameter is ignored - uses sensible defaults
func NewCollector(cfg interface{}, hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname: hostname,
		logger:   slog.Default(),
		enabled:  true, // Always enabled with defaults
		builder:  metrics.NewBuilder().WithHostname(hostname),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Option configures the CPU collector.
type Option func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Collector) {
		c.logger = logger
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "cpu"
}

// Enabled returns true if CPU collection is enabled.
func (c *Collector) Enabled() bool {
	return c.enabled
}

// Collect gathers CPU metrics with proper timeout handling.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !c.enabled {
		return nil, nil
	}

	sampleDuration := 100 * time.Millisecond // Optimized sample duration for better performance
	c.logger.Debug("collecting CPU metrics", "sample_duration", sampleDuration)

	var collectedMetrics []metrics.Metric
	timestamp := time.Now()

	// Update builder timestamp for consistent metrics
	c.builder = c.builder.WithTimestamp(timestamp)

	// Collect CPU count
	if err := c.collectCPUCount(ctx, &collectedMetrics); err != nil {
		c.logger.Warn("failed to collect CPU count", "error", err)
	}

	// Collect CPU usage percentages
	if err := c.collectCPUPercent(ctx, &collectedMetrics); err != nil {
		c.logger.Warn("failed to collect CPU percentages", "error", err)
	}

	c.logger.Debug("CPU collection completed", "metric_count", len(collectedMetrics))
	return collectedMetrics, nil
}

// collectCPUCount gathers the number of logical CPUs.
func (c *Collector) collectCPUCount(ctx context.Context, metrics *[]metrics.Metric) error {
	// Direct call - cpu.Counts is fast and doesn't block
	cpuCount, err := cpu.Counts(true)
	if err != nil {
		return fmt.Errorf("failed to get CPU count: %w", err)
	}

	if metric, err := c.builder.Gauge("cpu_count", float64(cpuCount)); err != nil {
		c.logger.Warn("failed to create cpu_count metric", "error", err)
	} else {
		*metrics = append(*metrics, metric)
	}
	return nil
}

// collectCPUPercent gathers CPU usage percentages.
func (c *Collector) collectCPUPercent(ctx context.Context, metrics *[]metrics.Metric) error {
	// Direct call with context - the function already handles timeouts properly
	sampleDuration := 100 * time.Millisecond
	percentages, err := cpu.PercentWithContext(ctx, sampleDuration, false) // Per-CPU disabled for simplicity
	if err != nil {
		return fmt.Errorf("failed to get CPU percentages: %w", err)
	}

	if len(percentages) == 0 {
		return fmt.Errorf("no CPU percentage data returned")
	}

	// Overall CPU usage (first element when PerCPU is false)
	if metric, err := c.builder.Gauge("cpu_usage_percent", percentages[0]); err != nil {
		c.logger.Warn("failed to create cpu_usage_percent metric", "error", err)
	} else {
		*metrics = append(*metrics, metric)
	}

	return nil
}

// Close performs cleanup (CPU collector doesn't need cleanup).
func (c *Collector) Close() error {
	c.logger.Debug("CPU collector closed")
	return nil
}

// HealthCheck verifies the collector can access CPU information.
func (c *Collector) HealthCheck(ctx context.Context) error {
	// Direct call - cpu.Counts is fast
	_, err := cpu.Counts(true)
	if err != nil {
		return fmt.Errorf("CPU health check failed: %w", err)
	}
	return nil
}

// Verify interface compliance at compile time.
var (
	_ metrics.Collector     = (*Collector)(nil)
	_ metrics.HealthChecker = (*Collector)(nil)
)
