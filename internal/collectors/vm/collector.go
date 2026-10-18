//go:build linux
// +build linux

// Package vm provides VM metrics collection for the Netwarden agent.
// VM monitoring is only supported on Linux systems.
package vm

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/cache"
	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

// vm_status values, as the platform decodes them.
const (
	vmStatusStopped = 0.0
	vmStatusRunning = 1.0
	vmStatusPaused  = 2.0
)

// Collector implements metrics.Collector for VM metrics.
type Collector struct {
	hostname   string
	logger     *slog.Logger
	builder    metrics.MetricBuilder
	enabled    bool
	config     config.VMConfig
	hypervisor HypervisorClient
	detector   *HypervisorDetector
}

// NewCollector creates a new VM metrics collector.
func NewCollector(vmConfig config.VMConfig, hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname: hostname,
		logger:   slog.Default(),
		enabled:  vmConfig.EnableVMs,
		config:   vmConfig,
		builder:  metrics.NewBuilder().WithHostname(hostname),
		detector: NewHypervisorDetector(),
	}

	for _, opt := range opts {
		opt(c)
	}

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
		if c.config.ProxmoxAPI == "" {
			// The collector reaches PVE only through its API, so a detected
			// node without an API address would otherwise collect nothing
			// silently.
			c.logger.Info("proxmox ve detected but proxmox_api is not set, no vm metrics will be collected; " +
				"set proxmox_api (e.g. https://127.0.0.1:8006) and proxmox_token_id/proxmox_token_secret in netwarden.conf")
		}
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

// Collect gathers VM inventory and resource metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	// Zero-valued counts would claim "no VMs" when the hypervisor simply
	// did not answer.
	if !c.Enabled() {
		return nil, nil
	}

	var collectedMetrics []metrics.Metric
	c.builder = c.builder.WithTimestamp(time.Now())

	vms, err := c.getVMsWithCache(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing VMs: %w", err)
	}

	if metric, err := c.builder.Gauge("vm_total_count", float64(len(vms))); err == nil {
		collectedMetrics = append(collectedMetrics, metric)
	}

	runningCount, stoppedCount, pausedCount := 0, 0, 0
	runningVMs := make([]VM, 0)

	for _, vm := range vms {
		labels := vmLabels(vm)

		// Any other state (libvirt "crashed", "in shutdown", Proxmox
		// "unknown", ...) gets no vm_status, since 0 would report it as
		// stopped. The platform shows such a guest as unknown.
		statusValue, statusKnown := 0.0, true
		switch vm.Status {
		case "running":
			statusValue = vmStatusRunning
			runningCount++
			runningVMs = append(runningVMs, vm)
		case "stopped":
			statusValue = vmStatusStopped
			stoppedCount++
		case "paused", "suspended":
			statusValue = vmStatusPaused
			pausedCount++
		default:
			statusKnown = false
		}

		if statusKnown {
			if metric, err := c.builder.GaugeWithLabels("vm_status", statusValue, labels); err == nil {
				collectedMetrics = append(collectedMetrics, metric)
			}
		}

		// VM configuration metrics. 0 means the hypervisor did not say
		// (e.g. unreadable domain XML); no guest has zero vCPUs or memory.
		if vm.CPUCount > 0 {
			if metric, err := c.builder.GaugeWithLabels("vm_cpu_count", float64(vm.CPUCount), labels); err == nil {
				collectedMetrics = append(collectedMetrics, metric)
			}
		}

		if vm.MemoryMB > 0 {
			if metric, err := c.builder.GaugeWithLabels("vm_memory_mb", float64(vm.MemoryMB), labels); err == nil {
				collectedMetrics = append(collectedMetrics, metric)
			}
		}

		if vm.DiskGB > 0 {
			if metric, err := c.builder.GaugeWithLabels("vm_disk_gb", float64(vm.DiskGB), labels); err == nil {
				collectedMetrics = append(collectedMetrics, metric)
			}
		}
	}

	if len(runningVMs) > 0 {
		statsMetrics := c.collectVMStatsConcurrently(ctx, runningVMs)
		collectedMetrics = append(collectedMetrics, statsMetrics...)
	}

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

// collectVMStatsConcurrently queries the hypervisor for each running VM's
// stats, VMParallelStats at a time. A VM whose query fails contributes
// nothing; the others are unaffected.
func (c *Collector) collectVMStatsConcurrently(ctx context.Context, vms []VM) []metrics.Metric {
	if len(vms) == 0 {
		return nil
	}

	workers := c.config.VMParallelStats
	if workers <= 0 {
		workers = 1
	}
	results := make([][]metrics.Metric, len(vms))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, vm := range vms {
		wg.Add(1)
		go func(i int, vm VM) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			statsCtx, cancel := context.WithTimeout(ctx, c.config.VMTimeout)
			defer cancel()

			stats, err := c.hypervisor.GetVMStats(statsCtx, vm)
			if err != nil {
				c.logger.Warn("failed to get VM stats", "vm", vm.Name, "error", err)
				return
			}
			var out []metrics.Metric
			c.collectVMStats(stats, vmLabels(vm), &out)
			results[i] = out
		}(i, vm)
	}
	wg.Wait()

	var all []metrics.Metric
	for _, r := range results {
		all = append(all, r...)
	}
	return all
}

// vmLabels is the label set shared by every series of one VM.
func vmLabels(vm VM) map[string]string {
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
		labels["vmid"] = strconv.Itoa(vm.VMID)
	}
	return labels
}

// collectVMStats turns one VM's stats into series. Optional groups are
// emitted only when the hypervisor reported them (see VMStats): an absent
// series is a gap, a zero would be a claim.
func (c *Collector) collectVMStats(stats *VMStats, labels map[string]string, out *[]metrics.Metric) {
	add := func(name string, value float64) {
		if m, err := c.builder.GaugeWithLabels(name, value, labels); err == nil {
			*out = append(*out, m)
		}
	}
	seconds := func(ns int64) float64 { return float64(ns) / 1e9 }

	// CPU
	if stats.CPUUsageKnown {
		add("vm_cpu_usage_percent", stats.CPUUsagePercent)
	}
	add("vm_cpu_time_seconds", seconds(stats.CPUTime))
	if stats.CPUSplitKnown {
		add("vm_cpu_user_seconds", seconds(stats.CPUUserTime))
		add("vm_cpu_system_seconds", seconds(stats.CPUSystemTime))
	}
	if stats.VCPUCurrent > 0 {
		add("vm_vcpu_current", float64(stats.VCPUCurrent))
	}
	if stats.VCPUWaitKnown {
		add("vm_vcpu_wait_seconds", seconds(stats.VCPUWaitTime))
	}
	if stats.VCPUDelayKnown {
		add("vm_vcpu_delay_seconds", seconds(stats.VCPUDelayTime))
	}

	// Memory, host view
	if stats.MemoryKnown {
		add("vm_memory_usage_mb", float64(stats.MemoryUsageMB))
		if stats.MemoryLimitKnown {
			add("vm_memory_available_mb", float64(stats.MemoryAvailableMB))
			add("vm_memory_usage_percent", stats.MemoryUsagePercent)
		}
	}

	// Memory, guest view
	if stats.GuestMemoryKnown {
		add("vm_guest_memory_total_mb", float64(stats.GuestMemoryTotalMB))
		add("vm_guest_memory_used_mb", float64(stats.GuestMemoryUsedMB))
		add("vm_guest_memory_usage_percent", stats.GuestMemoryUsagePercent)
	}
	if stats.MemoryFaultsKnown {
		add("vm_memory_swap_in_kb", float64(stats.SwapInKB))
		add("vm_memory_swap_out_kb", float64(stats.SwapOutKB))
		add("vm_memory_major_faults", float64(stats.MajorFaults))
		add("vm_memory_minor_faults", float64(stats.MinorFaults))
	}

	// Disk
	add("vm_disk_read_bytes", float64(stats.DiskReadBytes))
	add("vm_disk_write_bytes", float64(stats.DiskWriteBytes))
	add("vm_disk_read_ops", float64(stats.DiskReadOps))
	add("vm_disk_write_ops", float64(stats.DiskWriteOps))
	if stats.DiskTimingKnown {
		add("vm_disk_flush_ops", float64(stats.DiskFlushOps))
		add("vm_disk_read_time_seconds", seconds(stats.DiskReadTime))
		add("vm_disk_write_time_seconds", seconds(stats.DiskWriteTime))
		add("vm_disk_flush_time_seconds", seconds(stats.DiskFlushTime))
	}
	if stats.DiskAllocationKnown {
		add("vm_disk_allocation_bytes", float64(stats.DiskAllocationBytes))
		add("vm_disk_capacity_bytes", float64(stats.DiskCapacityBytes))
		if stats.DiskCapacityBytes > 0 {
			add("vm_disk_usage_percent", float64(stats.DiskAllocationBytes)/float64(stats.DiskCapacityBytes)*100)
		}
	}

	// Network
	add("vm_network_rx_bytes", float64(stats.NetworkRxBytes))
	add("vm_network_tx_bytes", float64(stats.NetworkTxBytes))
	add("vm_network_rx_packets", float64(stats.NetworkRxPackets))
	add("vm_network_tx_packets", float64(stats.NetworkTxPackets))
	if stats.NetworkErrorsKnown {
		add("vm_network_rx_errors", float64(stats.NetworkRxErrors))
		add("vm_network_tx_errors", float64(stats.NetworkTxErrors))
		add("vm_network_rx_dropped", float64(stats.NetworkRxDropped))
		add("vm_network_tx_dropped", float64(stats.NetworkTxDropped))
	}

	if stats.DirtyRateKnown {
		add("vm_dirty_rate_mb_per_second", stats.DirtyRateMBps)
	}

	// Only Proxmox reports uptime; libvirt exposes none.
	if stats.Uptime > 0 {
		add("vm_uptime_seconds", float64(stats.Uptime))
	}

	if g := stats.Guest; g != nil {
		c.collectGuestInfo(g, labels, out)
	}
}

// collectGuestInfo turns the guest agent's report into series: an identity
// gauge whose labels carry the OS facts, plus load, users and per-filesystem
// usage with the mountpoint as a label.
func (c *Collector) collectGuestInfo(g *GuestInfo, labels map[string]string, out *[]metrics.Metric) {
	withLabels := func(extra map[string]string) map[string]string {
		l := make(map[string]string, len(labels)+len(extra))
		for k, v := range labels {
			l[k] = v
		}
		for k, v := range extra {
			if v != "" {
				l[k] = v
			}
		}
		return l
	}
	add := func(name string, value float64, l map[string]string) {
		if m, err := c.builder.GaugeWithLabels(name, value, l); err == nil {
			*out = append(*out, m)
		}
	}

	if g.Hostname != "" || g.OSName != "" {
		add("vm_guest_info", 1, withLabels(map[string]string{
			"guest_hostname": g.Hostname,
			"guest_os":       g.OSName,
			"guest_os_id":    g.OSID,
			"guest_version":  g.OSVersion,
			"guest_kernel":   g.KernelRelease,
			"guest_arch":     g.Arch,
		}))
	}
	if g.LoadKnown {
		add("vm_guest_load1", g.Load1, labels)
		add("vm_guest_load5", g.Load5, labels)
		add("vm_guest_load15", g.Load15, labels)
	}
	if g.UsersKnown {
		add("vm_guest_users_count", float64(g.Users), labels)
	}
	for _, fs := range g.Filesystems {
		l := withLabels(map[string]string{"mountpoint": fs.Mountpoint, "fstype": fs.FSType, "device": fs.Name})
		add("vm_fs_total_bytes", float64(fs.TotalBytes), l)
		add("vm_fs_used_bytes", float64(fs.UsedBytes), l)
		add("vm_fs_usage_percent", float64(fs.UsedBytes)/float64(fs.TotalBytes)*100, l)
	}
}

// getVMsWithCache retrieves VMs using cache when possible.
func (c *Collector) getVMsWithCache(ctx context.Context) ([]VM, error) {
	cacheKey := fmt.Sprintf("vm:list:%s", c.hostname)

	if cached, ok := cache.Get(cacheKey); ok {
		if vms, ok := cached.([]VM); ok {
			c.logger.Debug("using cached VM list")
			return vms, nil
		}
	}

	c.logger.Debug("fetching fresh VM list")
	vms, err := c.hypervisor.ListVMs(ctx)
	if err != nil {
		return nil, err
	}
	vms = filterVMs(vms, c.config.VMInclude, c.config.VMExclude)

	cache.Set(cacheKey, vms, c.config.VMCacheTimeout)
	return vms, nil
}

// filterVMs applies the operator's vm_include / vm_exclude name globs. With
// no include list every VM is a candidate; an exclude match always wins.
func filterVMs(vms []VM, include, exclude []string) []VM {
	if len(include) == 0 && len(exclude) == 0 {
		return vms
	}
	matches := func(patterns []string, name string) bool {
		for _, p := range patterns {
			if ok, err := filepath.Match(p, name); err == nil && ok {
				return true
			}
		}
		return false
	}
	out := make([]VM, 0, len(vms))
	for _, vm := range vms {
		if len(include) > 0 && !matches(include, vm.Name) {
			continue
		}
		if matches(exclude, vm.Name) {
			continue
		}
		out = append(out, vm)
	}
	return out
}

// Close performs cleanup and closes any connections.
func (c *Collector) Close() error {
	if c.hypervisor != nil {
		return c.hypervisor.Close()
	}
	return nil
}

var _ metrics.Collector = (*Collector)(nil)
