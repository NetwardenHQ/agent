// Package memory provides memory metric collection with configurable
// swap and cache monitoring options.
package memory

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shirou/gopsutil/v4/mem"

	"netwarden/internal/metrics"
)

// Collector implements metrics.Collector for memory metrics.
type Collector struct {
	hostname string
	logger   *slog.Logger
	enabled  bool
}

// NewCollector creates a new memory metrics collector.
// cfg parameter is ignored - uses sensible defaults
func NewCollector(cfg interface{}, hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname: hostname,
		logger:   slog.Default(),
		enabled:  true,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Option configures the memory collector.
type Option func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Collector) {
		c.logger = logger
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "memory"
}

// Enabled returns true if memory collection is enabled.
func (c *Collector) Enabled() bool {
	return c.enabled
}

// Collect gathers memory metrics with proper timeout handling.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !c.enabled {
		return nil, nil
	}

	c.logger.Debug("collecting memory metrics")

	var collectedMetrics []metrics.Metric

	// Collect memory stats sequentially - they're fast enough
	if err := c.collectMemoryStats(ctx, &collectedMetrics); err != nil {
		c.logger.Warn("failed to collect memory stats", "error", err)
	}

	c.logger.Debug("memory collection completed", "metric_count", len(collectedMetrics))
	return collectedMetrics, nil
}

// collectMemoryStats gathers both virtual memory and swap stats.
func (c *Collector) collectMemoryStats(ctx context.Context, collectedMetrics *[]metrics.Metric) error {
	// Collect virtual memory stats
	vmStat, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		c.logger.Warn("failed to collect virtual memory stats", "error", err)
	} else {
		*collectedMetrics = append(*collectedMetrics,
			metrics.QuickGauge(c.hostname, "memory_total_bytes", float64(vmStat.Total)),
			metrics.QuickGauge(c.hostname, "memory_used_bytes", float64(vmStat.Used)),
			metrics.QuickGauge(c.hostname, "memory_free_bytes", float64(vmStat.Free)),
			metrics.QuickGauge(c.hostname, "memory_available_bytes", float64(vmStat.Available)),
			metrics.QuickGauge(c.hostname, "memory_usage_percent", vmStat.UsedPercent),
			metrics.QuickGauge(c.hostname, "memory_buffers_bytes", float64(vmStat.Buffers)),
			metrics.QuickGauge(c.hostname, "memory_cached_bytes", float64(vmStat.Cached)),
		)
	}

	// Collect swap memory stats
	swapStat, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		c.logger.Warn("failed to collect swap memory stats", "error", err)
	} else {
		*collectedMetrics = append(*collectedMetrics,
			metrics.QuickGauge(c.hostname, "swap_total_bytes", float64(swapStat.Total)),
			metrics.QuickGauge(c.hostname, "swap_used_bytes", float64(swapStat.Used)),
			metrics.QuickGauge(c.hostname, "swap_free_bytes", float64(swapStat.Free)),
			metrics.QuickGauge(c.hostname, "swap_usage_percent", swapStat.UsedPercent),
		)
	}

	return nil
}

// collectVirtualMemory is removed - using collectMemoryStats instead

// collectSwapMemory is removed - using collectMemoryStats instead

// Close performs cleanup (memory collector doesn't need cleanup).
func (c *Collector) Close() error {
	c.logger.Debug("memory collector closed")
	return nil
}

// HealthCheck verifies the collector can access memory information.
func (c *Collector) HealthCheck(ctx context.Context) error {
	// Direct call - mem.VirtualMemoryWithContext is fast
	_, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return fmt.Errorf("memory health check failed: %w", err)
	}
	return nil
}

// addGauge is removed - using QuickGauge helpers instead

// addGaugeWithLabels is removed - using QuickGaugeWithLabels helpers instead

// Verify interface compliance at compile time.
var (
	_ metrics.Collector     = (*Collector)(nil)
	_ metrics.HealthChecker = (*Collector)(nil)
)
