// Package cpu provides CPU metric collection.
package cpu

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// firstSampleWindow is how long the first Collect blocks to take a
// measurement. Later cycles use the CPU time accumulated since the previous
// cycle, which costs nothing and averages over the whole reporting interval.
const firstSampleWindow = 250 * time.Millisecond

// Collector implements metrics.Collector for CPU metrics.
type Collector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder

	mu   sync.Mutex
	prev *cpu.TimesStat // aggregate CPU times at the previous cycle; nil before the first
}

// NewCollector creates a new CPU metrics collector.
func NewCollector(hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname: hostname,
		logger:   slog.Default(),
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

// Enabled reports whether the collector is active. Registration is the switch.
func (c *Collector) Enabled() bool {
	return true
}

// Collect gathers the logical CPU count and the overall CPU utilization.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	c.builder = c.builder.WithTimestamp(time.Now())

	var collected []metrics.Metric

	count, err := cpu.CountsWithContext(ctx, true)
	if err != nil {
		c.logger.Warn("failed to get CPU count", "error", err)
	} else if m, err := c.builder.Gauge("cpu_count", float64(count)); err == nil {
		collected = append(collected, m)
	}

	percent, ok, err := c.usagePercent(ctx)
	if err != nil {
		c.logger.Warn("failed to get CPU usage", "error", err)
	} else if !ok {
		c.logger.Debug("no CPU time elapsed between samples; usage omitted")
	} else if m, err := c.builder.Gauge("cpu_usage_percent", percent); err == nil {
		collected = append(collected, m)
	}

	return collected, nil
}

// usagePercent returns the share of non-idle CPU time since the previous
// call, across all CPUs. The first call has no previous sample and blocks for
// firstSampleWindow to take one. ok is false when the two samples span no
// CPU time, so there is no measurement.
func (c *Collector) usagePercent(ctx context.Context) (percent float64, ok bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.prev == nil {
		first, err := aggregateTimes(ctx)
		if err != nil {
			return 0, false, err
		}
		select {
		case <-time.After(firstSampleWindow):
		case <-ctx.Done():
			return 0, false, ctx.Err()
		}
		c.prev = first
	}

	now, err := aggregateTimes(ctx)
	if err != nil {
		return 0, false, err
	}
	percent, ok = busyPercent(*c.prev, *now)
	c.prev = now
	return percent, ok, nil
}

// aggregateTimes returns the all-CPU TimesStat.
func aggregateTimes(ctx context.Context) (*cpu.TimesStat, error) {
	times, err := cpu.TimesWithContext(ctx, false)
	if err != nil {
		return nil, err
	}
	if len(times) == 0 {
		return nil, fmt.Errorf("no CPU time data returned")
	}
	return &times[0], nil
}

// busyPercent is the non-idle share of the CPU time elapsed between two
// samples, from 0 to 100. Idle and iowait both count as idle, as in
// gopsutil's cpu.Percent. ok is false when no CPU time elapsed or a counter
// went backwards: there is no measurement, and 0% would claim an idle machine.
func busyPercent(prev, now cpu.TimesStat) (float64, bool) {
	total := totalTime(now) - totalTime(prev)
	if total <= 0 {
		return 0, false
	}
	idle := (now.Idle + now.Iowait) - (prev.Idle + prev.Iowait)
	busy := total - idle
	if busy < 0 {
		return 0, true
	}
	if busy > total {
		return 100, true
	}
	return busy / total * 100, true
}

// Close performs cleanup (nothing to release).
func (c *Collector) Close() error {
	return nil
}

// HealthCheck verifies the collector can read CPU information.
func (c *Collector) HealthCheck(ctx context.Context) error {
	if _, err := cpu.CountsWithContext(ctx, true); err != nil {
		return fmt.Errorf("CPU health check failed: %w", err)
	}
	return nil
}

// totalTime sums every accounting bucket of a TimesStat. Guest time is
// already included in User/Nice on Linux, so it is left out to avoid
// double counting.
func totalTime(t cpu.TimesStat) float64 {
	return t.User + t.System + t.Idle + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal
}

// Verify interface compliance at compile time.
var (
	_ metrics.Collector     = (*Collector)(nil)
	_ metrics.HealthChecker = (*Collector)(nil)
)
