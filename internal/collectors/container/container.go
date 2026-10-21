// Package container provides container metrics collection for the Netwarden agent.
package container

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

const (
	// statsConcurrency is how many containers are queried for stats at once.
	statsConcurrency = 5

	// statsTimeout bounds one container's stats call.
	statsTimeout = 5 * time.Second
)

// Collector implements metrics.Collector for container metrics.
type Collector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder
	enabled  bool
	config   config.ContainerConfig
	monitor  *RuntimeMonitor

	// images holds the container-image inventory snapshot between Collect()
	// and Snapshots(). See container_images.go.
	images imageInventory
}

// NewCollector creates a new container metrics collector.
func NewCollector(containerConfig config.ContainerConfig, hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname: hostname,
		logger:   slog.Default(),
		enabled:  containerConfig.EnableContainers,
		config:   containerConfig,
		builder:  metrics.NewBuilder().WithHostname(hostname),
	}

	for _, opt := range opts {
		opt(c)
	}

	detector := NewRuntimeDetector(c.logger)
	runtime := detector.DetectRuntime(containerConfig)
	c.monitor = NewRuntimeMonitor(runtime, detector, containerConfig, c.logger)

	return c
}

// Option configures the container collector.
type Option func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Collector) {
		c.logger = logger
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "container"
}

// Enabled reports whether container collection is on and a runtime is
// reachable. The monitor throttles the reachability check itself.
func (c *Collector) Enabled() bool {
	return c.enabled && c.monitor.IsAvailable()
}

// Collect gathers per-container status and resource metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !c.Enabled() {
		return nil, nil
	}

	c.builder = c.builder.WithTimestamp(time.Now())
	runtime := c.monitor.GetClient()

	containers, err := runtime.ListContainers(ctx)
	if err != nil {
		// Report an error rather than a zero running count, which would
		// claim every container is down.
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	// Image inventory, built from the same list so it costs no extra
	// runtime calls.
	c.stageImages(containers)

	var collected []metrics.Metric
	running := make([]Container, 0, len(containers))
	for _, ct := range containers {
		status := 0.0
		if ct.Status == "running" {
			status = 1
			running = append(running, ct)
		}

		// The container id in the metric name gives each container its own
		// series.
		id := shortID(ct.ID)
		labels := c.labels(ct, runtime)
		if m, err := c.builder.GaugeWithLabels("container_status_"+id, status, labels); err == nil {
			collected = append(collected, m)
		}
		collected = append(collected, c.stateMetrics(id, ct, labels)...)
	}

	collected = append(collected, c.collectStats(ctx, runtime, running)...)

	if m, err := c.builder.Gauge("container_running_count", float64(len(running))); err == nil {
		collected = append(collected, m)
	}
	return collected, nil
}

// stateMetrics reports what container_status_ cannot: the exact state, the
// health check, the exit code of a stopped container and the restart count.
// The values are numeric because the platform reads them without labels; the
// codes are defined in container_state.go.
func (c *Collector) stateMetrics(id string, ct Container, labels map[string]string) []metrics.Metric {
	var out []metrics.Metric
	add := func(name string, v float64) {
		if m, err := c.builder.GaugeWithLabels(name+id, v, labels); err == nil {
			out = append(out, m)
		}
	}
	add("container_state_", stateCode(ct.Status))
	if v, ok := healthCode(ct.Health); ok {
		add("container_health_", v)
	}
	if ct.ExitCode != nil {
		add("container_exit_code_", float64(*ct.ExitCode))
	}
	if ct.Restarts != nil {
		add("container_restarts_", float64(*ct.Restarts))
	}
	return out
}

// labels is the label set shared by every series of one container.
func (c *Collector) labels(ct Container, runtime RuntimeClient) map[string]string {
	return map[string]string{
		"container":    ct.Name,
		"container_id": ct.ID,
		"image":        ct.Image,
		"runtime":      runtime.Name(),
	}
}

// shortID is the 12-character form of a container id, as the CLI shows it.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// collectStats queries the runtime for each running container's resource use,
// a few at a time. A container whose stats call fails contributes nothing;
// the others are unaffected.
func (c *Collector) collectStats(ctx context.Context, runtime RuntimeClient, containers []Container) []metrics.Metric {
	if len(containers) == 0 {
		return nil
	}

	results := make([][]metrics.Metric, len(containers))
	sem := make(chan struct{}, statsConcurrency)
	var wg sync.WaitGroup

	for i, ct := range containers {
		wg.Add(1)
		go func(i int, ct Container) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			statsCtx, cancel := context.WithTimeout(ctx, statsTimeout)
			defer cancel()

			stats, err := runtime.GetContainerStats(statsCtx, ct.ID)
			if err != nil {
				c.logger.Warn("failed to get container stats", "container", ct.Name, "error", err)
				return
			}
			results[i] = c.statsMetrics(stats, c.labels(ct, runtime))
		}(i, ct)
	}
	wg.Wait()

	var out []metrics.Metric
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

// statsMetrics turns one container's stats into series.
func (c *Collector) statsMetrics(stats *ContainerStats, labels map[string]string) []metrics.Metric {
	out := make([]metrics.Metric, 0, 8)
	add := func(name string, value float64) {
		if m, err := c.builder.GaugeWithLabels(name, value, labels); err == nil {
			out = append(out, m)
		}
	}

	// Only what the runtime actually reported (see ContainerStats).
	if stats.CPUKnown {
		// 100 = one core, as in `docker stats` / `podman stats`.
		add("container_cpu_usage_percent", stats.CPUPercent)
	}
	if stats.MemoryKnown {
		add("container_memory_usage_bytes", float64(stats.MemoryUsage))
		if stats.MemoryLimit > 0 {
			add("container_memory_limit_bytes", float64(stats.MemoryLimit))
			add("container_memory_usage_percent", float64(stats.MemoryUsage)/float64(stats.MemoryLimit)*100)
		}
	}
	if stats.NetworkKnown {
		add("container_network_rx_bytes", float64(stats.NetworkRxBytes))
		add("container_network_tx_bytes", float64(stats.NetworkTxBytes))
	}
	if stats.DiskKnown {
		add("container_disk_read_bytes", float64(stats.DiskReadBytes))
		add("container_disk_write_bytes", float64(stats.DiskWriteBytes))
	}
	return out
}

// Close releases the runtime connection.
func (c *Collector) Close() error {
	if c.monitor != nil {
		return c.monitor.Close()
	}
	return nil
}

// Verify interface compliance at compile time.
var _ metrics.Collector = (*Collector)(nil)
