// Package container provides container metrics collection for the Netwarden agent.
package container

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"netwarden/internal/config"
	"netwarden/internal/metrics"
)

// Collector implements metrics.Collector for container metrics.
type Collector struct {
	hostname    string
	logger      *slog.Logger
	builder     metrics.MetricBuilder
	enabled     bool
	config      config.ContainerConfig
	monitor     *RuntimeMonitor
	lastCollect time.Time
	// Availability caching to prevent excessive runtime checks
	availabilityMutex sync.RWMutex
	cachedAvailable   bool
	availableCacheExp time.Time
}

// NewCollector creates a new container metrics collector.
func NewCollector(cfg interface{}, hostname string, opts ...Option) *Collector {
	var containerConfig config.ContainerConfig

	// Parse configuration
	switch v := cfg.(type) {
	case config.ContainerConfig:
		containerConfig = v
	case *config.ContainerConfig:
		if v != nil {
			containerConfig = *v
		}
	default:
		// Default config if not provided
		containerConfig = config.ContainerConfig{
			EnableContainers: true, // Enable containers by default
			ContainerRuntime: "auto",
			StatsInterval:    30 * time.Second,
		}
	}

	c := &Collector{
		hostname: hostname,
		logger:   slog.Default(),
		enabled:  containerConfig.EnableContainers,
		config:   containerConfig,
		builder:  metrics.NewBuilder().WithHostname(hostname),
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	// Initialize runtime detection and monitoring
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

// Enabled returns true if container collection is enabled and runtime is available.
// Uses caching to prevent excessive availability checks.
func (c *Collector) Enabled() bool {
	if !c.enabled {
		return false
	}

	// Check cached availability first (2-minute cache)
	c.availabilityMutex.RLock()
	if time.Now().Before(c.availableCacheExp) {
		result := c.cachedAvailable
		c.availabilityMutex.RUnlock()
		return result
	}
	c.availabilityMutex.RUnlock()

	// Need to check availability
	c.availabilityMutex.Lock()
	defer c.availabilityMutex.Unlock()

	// Double-check pattern
	if time.Now().Before(c.availableCacheExp) {
		return c.cachedAvailable
	}

	// Check runtime availability
	runtimeAvailable := c.monitor.IsAvailable(context.Background())

	// Cache result (shorter cache for negative results)
	if runtimeAvailable {
		c.availableCacheExp = time.Now().Add(2 * time.Minute)
	} else {
		c.availableCacheExp = time.Now().Add(30 * time.Second)
	}
	c.cachedAvailable = runtimeAvailable

	return runtimeAvailable
}

// Collect gathers container metrics with proper timeout and error handling.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !c.enabled {
		return nil, nil
	}

	// Check if runtime is available (with monitoring and failover)
	if !c.monitor.IsAvailable(ctx) {
		return nil, nil
	}

	var collectedMetrics []metrics.Metric
	timestamp := time.Now()
	c.builder = c.builder.WithTimestamp(timestamp)

	// Get the current runtime client
	runtime := c.monitor.GetClient()

	// Get container list with caching
	containers, err := c.getContainersWithCache(ctx, runtime)
	if err != nil {
		c.logger.Warn("failed to list containers", "error", err)
		// Return basic metrics even on error
		return c.buildBasicMetrics(0, 0), nil
	}

	// System-level metrics
	// Note: Total count removed - ContainerWidget uses dashboard stats calculated from container_status metrics

	// Count running containers and collect basic metrics
	runningContainers := make([]Container, 0)
	for _, container := range containers {
		// Per-container basic metrics
		labels := map[string]string{
			"container":    container.Name,
			"container_id": container.ID,
			"image":        container.Image,
			"runtime":      runtime.Name(),
		}

		statusValue := 0.0
		if container.Status == "running" {
			statusValue = 1.0
			runningContainers = append(runningContainers, container)
		}

		// Create unique metric name to avoid database constraint conflicts
		idSuffix := container.ID
		if len(idSuffix) > 12 {
			idSuffix = idSuffix[:12]
		}
		statusMetricName := fmt.Sprintf("container_status_%s", idSuffix)
		if metric, err := c.builder.GaugeWithLabels(statusMetricName, statusValue, labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		} else {
			c.logger.Error("failed to create container_status metric", "container", container.Name, "error", err)
		}
	}

	// Collect detailed stats for running containers concurrently
	statsMetrics := c.collectContainerStatsConcurrently(ctx, runtime, runningContainers)
	collectedMetrics = append(collectedMetrics, statsMetrics...)

	// Running containers count
	if metric, err := c.builder.Gauge("container_running_count", float64(len(runningContainers))); err == nil {
		collectedMetrics = append(collectedMetrics, metric)
	}

	return collectedMetrics, nil
}

// collectContainerStats converts container stats to metrics.
func (c *Collector) collectContainerStats(stats *ContainerStats, labels map[string]string, metrics *[]metrics.Metric) {
	// CPU metrics
	if metric, err := c.builder.GaugeWithLabels("container_cpu_usage_percent", stats.CPUPercent, labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	// Memory metrics
	if metric, err := c.builder.GaugeWithLabels("container_memory_usage_bytes", float64(stats.MemoryUsage), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("container_memory_limit_bytes", float64(stats.MemoryLimit), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	// Memory usage percentage (if limit is available)
	if stats.MemoryLimit > 0 {
		memoryPercent := (float64(stats.MemoryUsage) / float64(stats.MemoryLimit)) * 100.0
		if metric, err := c.builder.GaugeWithLabels("container_memory_usage_percent", memoryPercent, labels); err == nil {
			*metrics = append(*metrics, metric)
		}
	}

	// Network metrics
	if metric, err := c.builder.GaugeWithLabels("container_network_rx_bytes", float64(stats.NetworkRxBytes), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("container_network_tx_bytes", float64(stats.NetworkTxBytes), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	// Disk I/O metrics
	if metric, err := c.builder.GaugeWithLabels("container_disk_read_bytes", float64(stats.DiskReadBytes), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("container_disk_write_bytes", float64(stats.DiskWriteBytes), labels); err == nil {
		*metrics = append(*metrics, metric)
	}
}

// getContainersWithCache retrieves containers using cache when possible.
func (c *Collector) getContainersWithCache(ctx context.Context, runtime RuntimeClient) ([]Container, error) {
	containers, err := runtime.ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	return containers, nil
}

// collectContainerStatsConcurrently collects stats for running containers in parallel.
func (c *Collector) collectContainerStatsConcurrently(ctx context.Context, runtime RuntimeClient, containers []Container) []metrics.Metric {
	if len(containers) == 0 {
		return nil
	}

	// Limit concurrency to avoid overwhelming the runtime
	maxWorkers := 5
	if len(containers) < maxWorkers {
		maxWorkers = len(containers)
	}

	type statsResult struct {
		metrics []metrics.Metric
		err     error
	}

	resultsChan := make(chan statsResult, len(containers))
	semaphore := make(chan struct{}, maxWorkers)

	// Use WaitGroup to ensure all goroutines complete
	var wg sync.WaitGroup
	wg.Add(len(containers))

	// Start workers
	for _, container := range containers {
		go func(container Container) {
			defer wg.Done()
			// Acquire semaphore with context cancellation support
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				// Context cancelled before we could acquire semaphore
				select {
				case resultsChan <- statsResult{err: ctx.Err()}:
				default:
					// Channel might be full, but we're shutting down anyway
				}
				return
			}

			// Create context with timeout for stats collection
			statsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			labels := map[string]string{
				"container":    container.Name,
				"container_id": container.ID,
				"image":        container.Image,
				"runtime":      runtime.Name(),
			}

			stats, err := runtime.GetContainerStats(statsCtx, container.ID)
			if err != nil {
				c.logger.Warn("failed to get container stats", "container", container.Name, "error", err)
				select {
				case resultsChan <- statsResult{err: err}:
				case <-ctx.Done():
					// Context cancelled while trying to send result
				}
				return
			}

			var metrics []metrics.Metric
			c.collectContainerStats(stats, labels, &metrics)
			select {
			case resultsChan <- statsResult{metrics: metrics}:
			case <-ctx.Done():
				// Context cancelled while trying to send result
			}
		}(container)
	}

	// Close results channel after all goroutines complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results with context cancellation support
	var allMetrics []metrics.Metric
collectLoop:
	for {
		select {
		case result, ok := <-resultsChan:
			if !ok {
				// Channel closed, all goroutines completed
				break collectLoop
			}
			if result.err == nil {
				allMetrics = append(allMetrics, result.metrics...)
			}
		case <-ctx.Done():
			// Context cancelled - wait briefly for goroutines to finish
			// Use a timeout to prevent hanging forever
			waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			waitDone := make(chan struct{})
			go func() {
				wg.Wait()
				close(waitDone)
			}()

			select {
			case <-waitDone:
				// All goroutines finished cleanly
			case <-waitCtx.Done():
				// Timeout - goroutines taking too long, but they'll clean up eventually
				c.logger.Warn("timeout waiting for container stats goroutines to complete")
			}
			return allMetrics
		}
	}

	return allMetrics
}

// buildBasicMetrics creates minimal metrics when container listing fails.
func (c *Collector) buildBasicMetrics(totalCount, runningCount int) []metrics.Metric {
	var metrics []metrics.Metric

	// Note: container_total_count removed - dashboard calculates total from container_status metrics

	if metric, err := c.builder.Gauge("container_running_count", float64(runningCount)); err == nil {
		metrics = append(metrics, metric)
	}

	return metrics
}

// GetRuntimeName returns the name of the currently active runtime.
func (c *Collector) GetRuntimeName() string {
	if c.monitor != nil {
		return c.monitor.GetClient().Name()
	}
	return "none"
}

// Close performs cleanup and closes any connections.
func (c *Collector) Close() error {
	if c.monitor != nil {
		return c.monitor.Close()
	}
	return nil
}

// Verify interface compliance at compile time
var _ metrics.Collector = (*Collector)(nil)
