//go:build linux
// +build linux

// Package vm provides VM metrics collection for the Netwarden agent.
// VM monitoring is only supported on Linux systems.
package vm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"netwarden/internal/cache"
	"netwarden/internal/config"
	"netwarden/internal/metrics"
)

// Collector implements metrics.Collector for VM metrics.
type Collector struct {
	hostname    string
	logger      *slog.Logger
	builder     metrics.MetricBuilder
	enabled     bool
	config      config.VMConfig
	hypervisor  HypervisorClient
	detector    *HypervisorDetector
	lastCollect time.Time
}

// NewCollector creates a new VM metrics collector.
func NewCollector(cfg interface{}, hostname string, opts ...Option) *Collector {
	var vmConfig config.VMConfig

	// Parse configuration
	switch v := cfg.(type) {
	case config.VMConfig:
		vmConfig = v
	case *config.VMConfig:
		if v != nil {
			vmConfig = *v
		}
	default:
		// Default config if not provided
		vmConfig = config.VMConfig{
			EnableVMs:       false,
			VMHypervisor:    "auto",
			StatsInterval:   30 * time.Second,
			VMTimeout:       30 * time.Second,
			VMCacheTimeout:  30 * time.Second,
			VMParallelStats: 5,
		}
	}

	c := &Collector{
		hostname: hostname,
		logger:   slog.Default(),
		enabled:  vmConfig.EnableVMs,
		config:   vmConfig,
		builder:  metrics.NewBuilder().WithHostname(hostname),
		detector: NewHypervisorDetector(),
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	// Initialize hypervisor client
	c.initializeHypervisor()

	return c
}

// Option configures the VM collector.
type Option func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Collector) {
		c.logger = logger
	}
}

// initializeHypervisor detects and initializes the appropriate hypervisor client.
func (c *Collector) initializeHypervisor() {
	var hypervisorType string

	if c.config.VMHypervisor == "auto" {
		hypervisorType = c.detector.DetectHypervisor()
	} else {
		hypervisorType = c.config.VMHypervisor
	}

	switch hypervisorType {
	case "proxmox":
		c.hypervisor = NewProxmoxClient(c.config, c.logger)
	case "libvirt", "kvm", "xen", "qemu":
		c.hypervisor = NewLibvirtClient(c.config, c.logger)
	default:
		c.hypervisor = &NoOpClient{}
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "vm"
}

// Enabled returns true if VM collection is enabled and hypervisor is available.
func (c *Collector) Enabled() bool {
	return c.enabled && c.hypervisor.IsAvailable()
}

// Collect gathers VM metrics with proper timeout and error handling.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !c.enabled {
		return nil, nil
	}

	// Check hypervisor availability with monitoring
	if !c.hypervisor.IsAvailable() {
		return c.buildBasicMetrics(0, 0, 0), nil
	}

	var collectedMetrics []metrics.Metric
	timestamp := time.Now()
	c.builder = c.builder.WithTimestamp(timestamp)

	// Get VM list with caching
	vms, err := c.getVMsWithCache(ctx)
	if err != nil {
		c.logger.Warn("failed to list VMs", "error", err)
		return c.buildBasicMetrics(0, 0, 0), nil
	}

	// System-level VM metrics
	if metric, err := c.builder.Gauge("vm_total_count", float64(len(vms))); err == nil {
		collectedMetrics = append(collectedMetrics, metric)
	}

	// Count VMs by status
	runningCount, stoppedCount, pausedCount := 0, 0, 0
	runningVMs := make([]VM, 0)

	for _, vm := range vms {
		// Basic VM metrics with labels
		labels := map[string]string{
			"vm":         vm.Name,
			"vm_id":      vm.ID,
			"hypervisor": vm.Hypervisor,
			"os_type":    vm.OSType,
		}

		// Add hypervisor-specific labels if available
		if vm.Node != "" {
			labels["node"] = vm.Node
		}
		if vm.VMID > 0 {
			labels["vmid"] = fmt.Sprintf("%d", vm.VMID)
		}

		var statusValue float64
		switch vm.Status {
		case "running":
			statusValue = 1.0
			runningCount++
			runningVMs = append(runningVMs, vm)
		case "stopped":
			statusValue = 0.0
			stoppedCount++
		case "paused", "suspended":
			statusValue = 0.5
			pausedCount++
		}

		if metric, err := c.builder.GaugeWithLabels("vm_status", statusValue, labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// VM configuration metrics
		if metric, err := c.builder.GaugeWithLabels("vm_cpu_count", float64(vm.CPUCount), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		if metric, err := c.builder.GaugeWithLabels("vm_memory_mb", float64(vm.MemoryMB), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		if vm.DiskGB > 0 {
			if metric, err := c.builder.GaugeWithLabels("vm_disk_gb", float64(vm.DiskGB), labels); err == nil {
				collectedMetrics = append(collectedMetrics, metric)
			}
		}
	}

	// Collect detailed stats for running VMs concurrently
	if len(runningVMs) > 0 {
		statsMetrics := c.collectVMStatsConcurrently(ctx, runningVMs)
		collectedMetrics = append(collectedMetrics, statsMetrics...)
	}

	// Status count metrics
	if metric, err := c.builder.Gauge("vm_running_count", float64(runningCount)); err == nil {
		collectedMetrics = append(collectedMetrics, metric)
	}
	if metric, err := c.builder.Gauge("vm_stopped_count", float64(stoppedCount)); err == nil {
		collectedMetrics = append(collectedMetrics, metric)
	}
	if metric, err := c.builder.Gauge("vm_paused_count", float64(pausedCount)); err == nil {
		collectedMetrics = append(collectedMetrics, metric)
	}

	return collectedMetrics, nil
}

// collectVMStatsConcurrently collects stats for running VMs in parallel.
func (c *Collector) collectVMStatsConcurrently(ctx context.Context, vms []VM) []metrics.Metric {
	if len(vms) == 0 {
		return nil
	}

	// Limit concurrency to avoid overwhelming the hypervisor
	maxWorkers := c.config.VMParallelStats
	if len(vms) < maxWorkers {
		maxWorkers = len(vms)
	}

	type statsResult struct {
		metrics []metrics.Metric
		err     error
	}

	resultsChan := make(chan statsResult, len(vms))
	semaphore := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	// Start workers
	for _, vm := range vms {
		wg.Add(1)
		go func(vm VM) {
			defer wg.Done()

			// Acquire semaphore with context cancellation support
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				resultsChan <- statsResult{err: ctx.Err()}
				return
			}

			// Create context with timeout for stats collection
			statsCtx, cancel := context.WithTimeout(ctx, c.config.VMTimeout)
			defer cancel()

			labels := map[string]string{
				"vm":         vm.Name,
				"vm_id":      vm.ID,
				"hypervisor": vm.Hypervisor,
				"os_type":    vm.OSType,
			}

			if vm.Node != "" {
				labels["node"] = vm.Node
			}
			if vm.VMID > 0 {
				labels["vmid"] = fmt.Sprintf("%d", vm.VMID)
			}

			stats, err := c.hypervisor.GetVMStats(statsCtx, vm.ID)
			if err != nil {
				c.logger.Warn("failed to get VM stats", "vm", vm.Name, "error", err)
				resultsChan <- statsResult{err: err}
				return
			}

			var metrics []metrics.Metric
			c.collectVMStats(stats, labels, &metrics)
			resultsChan <- statsResult{metrics: metrics}
		}(vm)
	}

	// Close results channel once all goroutines complete
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
				break collectLoop
			}
			if result.err == nil {
				allMetrics = append(allMetrics, result.metrics...)
			}
		case <-ctx.Done():
			break collectLoop
		}
	}

	return allMetrics
}

// collectVMStats converts VM stats to metrics.
func (c *Collector) collectVMStats(stats *VMStats, labels map[string]string, metrics *[]metrics.Metric) {
	// CPU metrics
	if metric, err := c.builder.GaugeWithLabels("vm_cpu_usage_percent", stats.CPUUsagePercent, labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_cpu_time_seconds", float64(stats.CPUTime)/1e9, labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	// Memory metrics
	if metric, err := c.builder.GaugeWithLabels("vm_memory_usage_mb", float64(stats.MemoryUsageMB), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_memory_available_mb", float64(stats.MemoryAvailableMB), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_memory_usage_percent", stats.MemoryUsagePercent, labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	// Disk I/O metrics
	if metric, err := c.builder.GaugeWithLabels("vm_disk_read_bytes", float64(stats.DiskReadBytes), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_disk_write_bytes", float64(stats.DiskWriteBytes), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_disk_read_ops", float64(stats.DiskReadOps), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_disk_write_ops", float64(stats.DiskWriteOps), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	// Network metrics
	if metric, err := c.builder.GaugeWithLabels("vm_network_rx_bytes", float64(stats.NetworkRxBytes), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_network_tx_bytes", float64(stats.NetworkTxBytes), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_network_rx_packets", float64(stats.NetworkRxPackets), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	if metric, err := c.builder.GaugeWithLabels("vm_network_tx_packets", float64(stats.NetworkTxPackets), labels); err == nil {
		*metrics = append(*metrics, metric)
	}

	// Uptime metric
	if metric, err := c.builder.GaugeWithLabels("vm_uptime_seconds", float64(stats.Uptime), labels); err == nil {
		*metrics = append(*metrics, metric)
	}
}

// getVMsWithCache retrieves VMs using cache when possible.
func (c *Collector) getVMsWithCache(ctx context.Context) ([]VM, error) {
	cacheKey := fmt.Sprintf("vm:list:%s", c.hostname)

	// Check cache first
	if cached, ok := cache.Get(cacheKey); ok {
		if vms, ok := cached.([]VM); ok {
			c.logger.Debug("using cached VM list")
			return vms, nil
		}
	}

	// Cache miss or expired, fetch from hypervisor
	c.logger.Debug("fetching fresh VM list")
	vms, err := c.hypervisor.ListVMs(ctx)
	if err != nil {
		return nil, err
	}

	// Cache the result with configured TTL
	cache.Set(cacheKey, vms, c.config.VMCacheTimeout)
	return vms, nil
}

// buildBasicMetrics creates minimal metrics when VM listing fails.
func (c *Collector) buildBasicMetrics(totalCount, runningCount, stoppedCount int) []metrics.Metric {
	var metrics []metrics.Metric

	if metric, err := c.builder.Gauge("vm_total_count", float64(totalCount)); err == nil {
		metrics = append(metrics, metric)
	}

	if metric, err := c.builder.Gauge("vm_running_count", float64(runningCount)); err == nil {
		metrics = append(metrics, metric)
	}

	if metric, err := c.builder.Gauge("vm_stopped_count", float64(stoppedCount)); err == nil {
		metrics = append(metrics, metric)
	}

	return metrics
}

// GetHypervisorName returns the name of the currently active hypervisor.
func (c *Collector) GetHypervisorName() string {
	if c.hypervisor != nil {
		return c.hypervisor.Name()
	}
	return "none"
}

// Close performs cleanup and closes any connections.
func (c *Collector) Close() error {
	if c.hypervisor != nil {
		return c.hypervisor.Close()
	}
	return nil
}

// Verify interface compliance at compile time
var _ metrics.Collector = (*Collector)(nil)
