// Package disk provides disk usage metric collection.
package disk

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"netwarden/internal/metrics"
)

// Collector implements metrics.Collector for disk metrics.
type Collector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder
	// Partition cache to avoid repeated disk discovery calls
	partitionsMutex    sync.RWMutex
	cachedPartitions   []disk.PartitionStat
	partitionsCacheExp time.Time
}

// NewCollector creates a new disk metrics collector.
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

// Option configures the disk collector.
type Option func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Collector) {
		c.logger = logger
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "disk"
}

// Enabled returns true (disk collection is always enabled when registered).
func (c *Collector) Enabled() bool {
	return true
}

// Collect gathers disk usage metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	c.logger.Debug("collecting disk metrics")

	var collectedMetrics []metrics.Metric
	timestamp := time.Now()

	// Update builder timestamp for consistent metrics
	c.builder = c.builder.WithTimestamp(timestamp)

	// Get disk partitions with caching (10-minute cache)
	partitions, err := c.getPartitionsWithCache(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get disk partitions: %w", err)
	}

	// On Windows, ensure we have at least C:\ drive
	// Sometimes gopsutil might not return all drives properly
	if runtime.GOOS == "windows" && len(partitions) == 0 {
		// Manually add C: as a fallback (match what gopsutil returns)
		partitions = append(partitions, disk.PartitionStat{
			Device:     "C:",
			Mountpoint: "C:",
			Fstype:     "NTFS",
		})
	}

	// Track if we found C:\ on Windows
	foundCDrive := false
	if runtime.GOOS == "windows" {
		for _, p := range partitions {
			if p.Mountpoint == "C:" || p.Mountpoint == "C:\\" {
				foundCDrive = true
				break
			}
		}
		// If C: drive not found, add it (use "C:" to match what gopsutil returns)
		if !foundCDrive {
			partitions = append([]disk.PartitionStat{{
				Device:     "C:",
				Mountpoint: "C:",
				Fstype:     "NTFS",
			}}, partitions...)
		}
	}

	for _, partition := range partitions {
		// Skip certain Windows system partitions
		if runtime.GOOS == "windows" {
			// Skip recovery and system partitions by checking opts
			skipPartition := false
			for _, opt := range partition.Opts {
				if opt == "hidden" || opt == "system" {
					skipPartition = true
					break
				}
			}
			if skipPartition {
				c.logger.Debug("skipping system partition", "device", partition.Device, "opts", partition.Opts)
				continue
			}
			// Skip if no mountpoint (unmounted volumes)
			if partition.Mountpoint == "" {
				continue
			}
		}

		// Skip virtual/temporary filesystems on Linux
		if runtime.GOOS == "linux" {
			// Skip squashfs (snap packages and compressed filesystems)
			if partition.Fstype == "squashfs" {
				c.logger.Debug("skipping squashfs filesystem", "device", partition.Device, "mountpoint", partition.Mountpoint)
				continue
			}

			// Skip loop devices (used by snap and other virtual mounts)
			if strings.HasPrefix(partition.Device, "/dev/loop") {
				c.logger.Debug("skipping loop device", "device", partition.Device, "mountpoint", partition.Mountpoint)
				continue
			}

			// Skip virtual/temporary filesystems by type
			if partition.Fstype == "tmpfs" || partition.Fstype == "devtmpfs" ||
				partition.Fstype == "sysfs" || partition.Fstype == "proc" ||
				partition.Fstype == "overlay" || partition.Fstype == "overlay2" ||
				partition.Fstype == "aufs" {
				c.logger.Debug("skipping virtual filesystem", "device", partition.Device, "fstype", partition.Fstype)
				continue
			}

			// Skip container overlay storage paths
			// These are bind mounts or subdirectories that appear as regular filesystems (ext4, xfs)
			// but are actually container runtime storage and pollute disk metrics
			if isContainerOverlayPath(partition.Mountpoint) {
				c.logger.Debug("skipping container overlay storage path",
					"device", partition.Device,
					"mountpoint", partition.Mountpoint,
					"fstype", partition.Fstype)
				continue
			}
		}

		// Get usage stats for each partition
		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			c.logger.Warn("failed to get disk usage", "partition", partition.Device, "error", err)
			continue
		}

		// Skip if total size is 0 (e.g., special filesystems)
		if usage.Total == 0 {
			continue
		}

		labels := map[string]string{
			"device":     partition.Device,
			"mountpoint": partition.Mountpoint,
			"fstype":     partition.Fstype,
		}

		// Create composite metric name with mountpoint
		// This ensures each partition has unique metrics in the database
		metricSuffix := ":" + partition.Mountpoint

		// Disk usage percentage
		usagePercent := float64(usage.Used) / float64(usage.Total) * 100
		if metric, err := c.builder.GaugeWithLabels("disk_usage_percent"+metricSuffix, usagePercent, labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Total disk space (in bytes)
		if metric, err := c.builder.GaugeWithLabels("disk_total_bytes"+metricSuffix, float64(usage.Total), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Used disk space (in bytes)
		if metric, err := c.builder.GaugeWithLabels("disk_used_bytes"+metricSuffix, float64(usage.Used), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Free disk space (in bytes)
		if metric, err := c.builder.GaugeWithLabels("disk_free_bytes"+metricSuffix, float64(usage.Free), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}
	}

	c.logger.Debug("disk metrics collected", "count", len(collectedMetrics))
	return collectedMetrics, nil
}

// HealthCheck performs a health check of the disk collector.
func (c *Collector) HealthCheck(ctx context.Context) error {
	// Simple health check - try to get partitions
	_, err := disk.Partitions(false)
	if err != nil {
		return fmt.Errorf("disk collector health check failed: %w", err)
	}
	return nil
}

// getPartitionsWithCache retrieves disk partitions with caching to reduce system calls.
func (c *Collector) getPartitionsWithCache(ctx context.Context) ([]disk.PartitionStat, error) {
	// Check cache first (10-minute cache for disk partition discovery)
	c.partitionsMutex.RLock()
	if time.Now().Before(c.partitionsCacheExp) && len(c.cachedPartitions) > 0 {
		result := c.cachedPartitions
		c.partitionsMutex.RUnlock()
		c.logger.Debug("using cached disk partitions", "count", len(result))
		return result, nil
	}
	c.partitionsMutex.RUnlock()

	// Need to refresh cache
	c.partitionsMutex.Lock()
	defer c.partitionsMutex.Unlock()

	// Double-check pattern
	if time.Now().Before(c.partitionsCacheExp) && len(c.cachedPartitions) > 0 {
		return c.cachedPartitions, nil
	}

	// Get fresh partition list
	partitions, err := disk.Partitions(false)
	if err != nil {
		// Use cached partitions if available, even if expired
		if len(c.cachedPartitions) > 0 {
			c.logger.Warn("failed to refresh disk partitions, using cached", "error", err)
			return c.cachedPartitions, nil
		}
		return nil, err
	}

	// Update cache
	c.cachedPartitions = partitions
	c.partitionsCacheExp = time.Now().Add(10 * time.Minute)

	c.logger.Debug("refreshed disk partitions cache", "count", len(partitions))
	return partitions, nil
}

// Close performs any necessary cleanup.
func (c *Collector) Close() error {
	return nil
}

// isContainerOverlayPath checks if a mountpoint is a container overlay storage path.
// Container runtimes (Docker, Podman, containerd, LXD, etc.) use overlay filesystems
// for layered container storage. These paths pollute disk metrics and should be filtered out.
func isContainerOverlayPath(mountpoint string) bool {
	// Container overlay storage paths to filter
	containerPaths := []string{
		// Docker overlay storage
		"/var/lib/docker/overlay2/",
		"/var/lib/docker/overlay/",
		"/var/lib/docker/containers/",

		// Podman/CRI-O overlay storage (rootful)
		"/var/lib/containers/storage/overlay",
		"/var/lib/containers/storage/vfs",

		// containerd snapshotter storage
		"/var/lib/containerd/io.containerd.snapshotter",

		// LXD/LXC storage pools
		"/var/lib/lxd/storage-pools/",
		"/var/snap/lxd/common/lxd/storage-pools/",

		// Kubernetes kubelet ephemeral storage
		"/var/lib/kubelet/pods/",

		// k3s/Rancher container storage
		"/var/lib/rancher/k3s/agent/containerd/",
		"/var/lib/rancher/rke2/agent/containerd/",

		// Container runtime directories
		"/run/containers/storage/",

		// Synology Container Manager (Docker) storage
		"/volume1/@docker/",
		"/volume1/@appdata/ContainerManager/",
	}

	// Check if mountpoint starts with any container path
	for _, containerPath := range containerPaths {
		if strings.HasPrefix(mountpoint, containerPath) {
			return true
		}
	}

	// Check for rootless container storage in user home directories
	// Pattern: /home/<user>/.local/share/containers/storage/
	if strings.Contains(mountpoint, ".local/share/containers/storage/") {
		return true
	}

	// Check for rootless container storage in root home
	// Pattern: /root/.local/share/containers/storage/
	if strings.Contains(mountpoint, "/root/.local/share/containers/storage/") {
		return true
	}

	return false
}
