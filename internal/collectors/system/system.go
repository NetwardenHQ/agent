// Package system provides system metric collection with configurable
// uptime monitoring and cached update checking.
package system

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"

	"netwarden/internal/cache"
	"netwarden/internal/config"
	"netwarden/internal/metrics"
)

// updateInfo represents update check result.
type updateInfo struct {
	Count int
}

// Collector implements metrics.Collector for system metrics.
type Collector struct {
	config   config.SystemConfig
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder
}

// NewCollector creates a new system metrics collector.
func NewCollector(cfg config.SystemConfig, hostname string, opts ...Option) *Collector {
	c := &Collector{
		config:   cfg,
		hostname: hostname,
		logger:   slog.Default(),
		builder:  metrics.NewBuilder().WithHostname(hostname),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Option configures the system collector.
type Option func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Collector) {
		c.logger = logger
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "system"
}

// Enabled returns true if system collection is enabled.
func (c *Collector) Enabled() bool {
	return c.config.Enabled
}

// Collect gathers system metrics with proper timeout handling.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !c.config.Enabled {
		return nil, nil
	}

	c.logger.Debug("collecting system metrics")

	var collectedMetrics []metrics.Metric
	timestamp := time.Now()

	// Update builder timestamp for consistent metrics
	c.builder = c.builder.WithTimestamp(timestamp)

	// Collect uptime if enabled
	if c.config.CollectUptime {
		if err := c.collectUptime(ctx, &collectedMetrics); err != nil {
			c.logger.Warn("failed to collect uptime", "error", err)
		}
	}

	// Collect load averages (Unix-like systems)
	if runtime.GOOS != "windows" {
		if err := c.collectLoadAverage(ctx, &collectedMetrics); err != nil {
			c.logger.Warn("failed to collect load average", "error", err)
		}
	}

	// Collect update information from cache (populated by background goroutine in agent)
	// This no longer blocks - we just read cached values if they exist
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		if err := c.collectUpdateInfoFromCache(&collectedMetrics); err != nil {
			c.logger.Debug("no cached update info available", "error", err)
		}
	}

	// Collect user count
	if err := c.collectUserCount(ctx, &collectedMetrics); err != nil {
		c.logger.Warn("failed to collect user count", "error", err)
	}

	// Collect process count
	if err := c.collectProcessCount(ctx, &collectedMetrics); err != nil {
		c.logger.Warn("failed to collect process count", "error", err)
	}

	// Collect system info
	if err := c.collectSystemInfo(ctx, &collectedMetrics); err != nil {
		c.logger.Warn("failed to collect system info", "error", err)
	}

	c.logger.Debug("system collection completed", "metric_count", len(collectedMetrics))
	return collectedMetrics, nil
}

// collectUptime gathers system uptime information.
func (c *Collector) collectUptime(ctx context.Context, metrics *[]metrics.Metric) error {
	// Direct call - host.UptimeWithContext is fast
	uptime, err := host.UptimeWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get uptime: %w", err)
	}

	c.addGauge(metrics, "system_uptime", float64(uptime))
	return nil
}

// collectLoadAverage gathers system load averages (Unix-like systems only).
func (c *Collector) collectLoadAverage(ctx context.Context, metrics *[]metrics.Metric) error {
	// Direct call - load.AvgWithContext is fast
	loadAvg, err := load.AvgWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get load average: %w", err)
	}

	c.addGauge(metrics, "system_load1", loadAvg.Load1)
	c.addGauge(metrics, "system_load5", loadAvg.Load5)
	c.addGauge(metrics, "system_load15", loadAvg.Load15)

	return nil
}

// collectUpdateInfoFromCache reads cached update information populated by the background goroutine.
// This is non-blocking - if cache doesn't exist, we skip the metric (returns error).
func (c *Collector) collectUpdateInfoFromCache(metrics *[]metrics.Metric) error {
	cacheKey := fmt.Sprintf("system:updates:%s", c.hostname)

	// Check cache for update info populated by background goroutine
	cached, ok := cache.Get(cacheKey)
	if !ok {
		// Cache not populated yet - background check hasn't run
		return fmt.Errorf("update cache not populated yet")
	}

	// Parse cached data (map format from agent goroutine)
	updateData, ok := cached.(map[string]interface{})
	if !ok {
		// Legacy cache format - try old updateInfo struct
		if info, ok := cached.(*updateInfo); ok {
			c.addGauge(metrics, "system_updates_available_count", float64(info.Count))
			c.logger.Debug("using legacy cached update count", "count", info.Count)
			return nil
		}
		return fmt.Errorf("invalid cache data format")
	}

	// Extract counts from map
	if count, ok := updateData["count"].(int); ok {
		c.addGauge(metrics, "system_updates_available_count", float64(count))
		c.logger.Debug("using cached update count from background check", "count", count)
	}

	if securityCount, ok := updateData["security_count"].(int); ok {
		c.addGauge(metrics, "system_security_updates_count", float64(securityCount))
		c.logger.Debug("using cached security update count from background check", "count", securityCount)
	}

	return nil
}

// collectUserCount gathers the number of currently logged-in users
func (c *Collector) collectUserCount(ctx context.Context, metrics *[]metrics.Metric) error {
	var userCount int
	var err error

	// Direct call - platform-specific implementations are fast
	if runtime.GOOS == "windows" {
		userCount, err = getWindowsUserCount(ctx)
	} else {
		userCount, err = getUnixUserCount(ctx)
	}

	if err != nil {
		c.logger.Warn("failed to get user count",
			"component", "collector",
			"type", "system",
			"error", err)
		// Don't fail collection, just return 0
		c.addGauge(metrics, "connected_users_count", 0)
		return nil
	}

	c.logger.Debug("collected user count", "count", userCount)
	c.addGauge(metrics, "connected_users_count", float64(userCount))
	return nil
}

// collectProcessCount gathers the total number of running processes
func (c *Collector) collectProcessCount(ctx context.Context, metrics *[]metrics.Metric) error {
	var processCount int
	var err error

	// Direct call - platform-specific implementations are fast
	if runtime.GOOS == "windows" {
		processCount, err = getWindowsProcessCount(ctx)
	} else {
		processCount, err = getUnixProcessCount(ctx)
	}

	if err != nil {
		c.logger.Warn("failed to get process count",
			"component", "collector",
			"type", "system",
			"error", err)
		// Don't fail collection, just return 0
		c.addGauge(metrics, "processes_running_count", 0)
		return nil
	}

	c.logger.Debug("collected process count", "count", processCount)
	c.addGauge(metrics, "processes_running_count", float64(processCount))
	return nil
}

// Close performs cleanup (system collector doesn't need cleanup).
func (c *Collector) Close() error {
	c.logger.Debug("system collector closed")
	return nil
}

// HealthCheck verifies the collector can access system information.
func (c *Collector) HealthCheck(ctx context.Context) error {
	// Direct call - host.InfoWithContext is fast
	_, err := host.InfoWithContext(ctx)
	if err != nil {
		return fmt.Errorf("system health check failed: %w", err)
	}
	return nil
}

// addGauge is a helper method to add gauge metrics with error handling.
func (c *Collector) addGauge(metrics *[]metrics.Metric, name string, value float64) {
	metric, err := c.builder.Gauge(name, value)
	if err != nil {
		c.logger.Warn("failed to create gauge metric", "name", name, "error", err)
		return
	}
	*metrics = append(*metrics, metric)
}

// addGaugeWithLabels is a helper method to add gauge metrics with labels and error handling.
func (c *Collector) addGaugeWithLabels(metrics *[]metrics.Metric, name string, value float64, labels map[string]string) {
	metric, err := c.builder.GaugeWithLabels(name, value, labels)
	if err != nil {
		c.logger.Warn("failed to create gauge metric with labels", "name", name, "error", err)
		return
	}
	*metrics = append(*metrics, metric)
}

// collectSystemInfo gathers basic system information as a metric with caching.
func (c *Collector) collectSystemInfo(ctx context.Context, metricsOut *[]metrics.Metric) error {
	cacheKey := fmt.Sprintf("system:info:%s", c.hostname)

	// Check cache first (15-minute cache for static system info)
	if cached, ok := cache.Get(cacheKey); ok {
		if cachedMetric, ok := cached.(metrics.Metric); ok {
			c.logger.Debug("using cached system info")
			// Update timestamp on cached metric to current collection time
			cachedMetric.Timestamp = time.Now()
			*metricsOut = append(*metricsOut, cachedMetric)
			return nil
		}
	}

	// Cache miss, collect fresh system info
	// Direct call - host.InfoWithContext is fast
	hostInfo, err := host.InfoWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get host info: %w", err)
	}

	// Create labels with system information
	labels := map[string]string{
		"os":             hostInfo.OS,
		"platform":       hostInfo.Platform,
		"family":         hostInfo.PlatformFamily,
		"version":        hostInfo.PlatformVersion,
		"arch":           runtime.GOARCH,
		"kernel_version": hostInfo.KernelVersion,
	}

	// Add Linux distribution info if available
	if runtime.GOOS == "linux" {
		if distro, distroVersion := getLinuxDistribution(); distro != "" {
			labels["distro"] = distro
			if distroVersion != "" {
				labels["distro_version"] = distroVersion
			}
		}
	}

	// Create system info metric
	metric, err := c.builder.GaugeWithLabels("system_info", 1.0, labels)
	if err != nil {
		c.logger.Warn("failed to create system_info metric", "error", err)
		return nil
	}

	// Cache the metric for 15 minutes
	cache.Set(cacheKey, metric, 15*time.Minute)

	*metricsOut = append(*metricsOut, metric)
	c.logger.Debug("updated system info cache")

	return nil
}

// getLinuxDistribution attempts to determine the Linux distribution.
func getLinuxDistribution() (string, string) {
	// Check for Synology DSM first (before standard checks)
	if distro, version := parseSynologyVersion("/etc.defaults/VERSION"); distro != "" {
		return distro, version
	}

	// Try /etc/os-release first (standard)
	if distro, version := parseOSRelease("/etc/os-release"); distro != "" {
		return distro, version
	}

	// Try /etc/lsb-release (Ubuntu/Debian)
	if distro, version := parseLSBRelease("/etc/lsb-release"); distro != "" {
		return distro, version
	}

	// Try other distribution-specific files
	distroFiles := map[string]string{
		"/etc/redhat-release": "redhat",
		"/etc/centos-release": "centos",
		"/etc/fedora-release": "fedora",
		"/etc/debian_version": "debian",
		"/etc/alpine-release": "alpine",
	}

	for file, distro := range distroFiles {
		if _, err := os.Stat(file); err == nil {
			return distro, ""
		}
	}

	return "", ""
}

// parseOSRelease parses /etc/os-release format.
func parseOSRelease(filename string) (string, string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", ""
	}

	var distro, version string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			distro = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}

	return distro, version
}

// parseLSBRelease parses /etc/lsb-release format.
func parseLSBRelease(filename string) (string, string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", ""
	}

	var distro, version string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "DISTRIB_ID=") {
			distro = strings.ToLower(strings.TrimPrefix(line, "DISTRIB_ID="))
		} else if strings.HasPrefix(line, "DISTRIB_RELEASE=") {
			version = strings.TrimPrefix(line, "DISTRIB_RELEASE=")
		}
	}

	return distro, version
}

// parseSynologyVersion parses Synology DSM version information.
func parseSynologyVersion(filename string) (string, string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", ""
	}

	var osName, productVersion, hwModel string
	lines := strings.Split(string(data), "\n")

	// Parse VERSION file (shell variable format)
	for _, line := range lines {
		if strings.HasPrefix(line, "os_name=") {
			osName = strings.Trim(strings.TrimPrefix(line, "os_name="), `"`)
		} else if strings.HasPrefix(line, "productversion=") {
			productVersion = strings.Trim(strings.TrimPrefix(line, "productversion="), `"`)
		}
	}

	// Only proceed if this is DSM
	if osName != "DSM" {
		return "", ""
	}

	// Try to get hardware model
	if hwData, err := os.ReadFile("/proc/sys/kernel/syno_hw_version"); err == nil {
		hwModel = strings.TrimSpace(string(hwData))
	}

	// Build version string: "DSM 7.3 (DS220+)" or just "DSM 7.3"
	var version string
	if productVersion != "" {
		version = "DSM " + productVersion
		if hwModel != "" {
			version = version + " (" + hwModel + ")"
		}
	}

	return "synology", version
}

// Verify interface compliance at compile time.
var (
	_ metrics.Collector     = (*Collector)(nil)
	_ metrics.HealthChecker = (*Collector)(nil)
)
