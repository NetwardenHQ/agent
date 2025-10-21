// Package network provides network metric collection.
package network

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"

	"netwarden/internal/config"
	"netwarden/internal/metrics"
)

const (
	maxInterfaces          = 10 // Maximum number of interfaces to monitor
	interfaceCacheTTL      = 5 * time.Minute
	defaultGatewayCacheTTL = 5 * time.Minute
)

// Collector implements metrics.Collector for network metrics.
type Collector struct {
	config   config.NetworkConfig
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder

	// Cache for interface list
	interfacesMutex    sync.RWMutex
	cachedInterfaces   []gopsnet.InterfaceStat
	interfacesCacheExp time.Time

	// Cache for default interface
	defaultIfaceMutex sync.RWMutex
	defaultIface      string
	defaultIfaceExp   time.Time
}

// NewCollector creates a new network metrics collector.
func NewCollector(cfg config.NetworkConfig, hostname string, opts ...Option) *Collector {
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

// Option configures the network collector.
type Option func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Collector) {
		c.logger = logger
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "network"
}

// Enabled returns true if network collection is enabled.
func (c *Collector) Enabled() bool {
	return c.config.EnableNetwork
}

// Collect gathers network metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !c.config.EnableNetwork {
		return nil, nil
	}

	c.logger.Debug("collecting network metrics")

	var collectedMetrics []metrics.Metric
	timestamp := time.Now()

	// Update builder timestamp for consistent metrics
	c.builder = c.builder.WithTimestamp(timestamp)

	// Get default interface
	defaultIface, err := c.getDefaultInterfaceWithCache()
	if err != nil {
		c.logger.Warn("failed to get default interface", "error", err)
		// Continue anyway - we can still collect stats for other interfaces
	}

	// Get interfaces to monitor
	interfacesToMonitor, err := c.getInterfacesToMonitor(defaultIface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	if len(interfacesToMonitor) == 0 {
		c.logger.Warn("no network interfaces to monitor")
		return nil, nil
	}

	c.logger.Debug("monitoring network interfaces",
		"count", len(interfacesToMonitor),
		"default", defaultIface)

	// Get IO counters for all interfaces
	ioCounters, err := gopsnet.IOCounters(true) // pernic=true
	if err != nil {
		return nil, fmt.Errorf("failed to get network IO counters: %w", err)
	}

	// Convert to map for easy lookup
	ioCountersMap := make(map[string]gopsnet.IOCountersStat)
	for _, counter := range ioCounters {
		ioCountersMap[counter.Name] = counter
	}

	// Collect metrics for each monitored interface
	for _, iface := range interfacesToMonitor {
		// Get IO stats for this interface
		ioStats, ok := ioCountersMap[iface.Name]
		if !ok {
			c.logger.Debug("no IO stats for interface", "interface", iface.Name)
			continue
		}

		isDefault := iface.Name == defaultIface

		// Create labels
		labels := map[string]string{
			"interface":  iface.Name,
			"mac":        iface.HardwareAddr,
			"is_default": fmt.Sprintf("%v", isDefault),
		}

		// Network interface info (gauge)
		if metric, err := c.builder.GaugeWithLabels("network_interface_info", 1.0, labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Bytes sent (counter)
		if metric, err := c.builder.CounterWithLabels("network_bytes_sent_total", float64(ioStats.BytesSent), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Bytes received (counter)
		if metric, err := c.builder.CounterWithLabels("network_bytes_recv_total", float64(ioStats.BytesRecv), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Packets sent (counter)
		if metric, err := c.builder.CounterWithLabels("network_packets_sent_total", float64(ioStats.PacketsSent), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Packets received (counter)
		if metric, err := c.builder.CounterWithLabels("network_packets_recv_total", float64(ioStats.PacketsRecv), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Errors in (counter)
		if metric, err := c.builder.CounterWithLabels("network_errors_in_total", float64(ioStats.Errin), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Errors out (counter)
		if metric, err := c.builder.CounterWithLabels("network_errors_out_total", float64(ioStats.Errout), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Dropped in (counter)
		if metric, err := c.builder.CounterWithLabels("network_drop_in_total", float64(ioStats.Dropin), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}

		// Dropped out (counter)
		if metric, err := c.builder.CounterWithLabels("network_drop_out_total", float64(ioStats.Dropout), labels); err == nil {
			collectedMetrics = append(collectedMetrics, metric)
		}
	}

	c.logger.Debug("network metrics collected", "count", len(collectedMetrics))
	return collectedMetrics, nil
}

// getInterfacesToMonitor returns the list of interfaces to monitor based on config.
func (c *Collector) getInterfacesToMonitor(defaultIface string) ([]gopsnet.InterfaceStat, error) {
	// Get all interfaces with cache
	allInterfaces, err := c.getInterfacesWithCache(context.Background())
	if err != nil {
		return nil, err
	}

	var result []gopsnet.InterfaceStat

	// If specific interfaces are configured, use those
	if len(c.config.MonitoredInterfaces) > 0 {
		for _, iface := range allInterfaces {
			for _, configured := range c.config.MonitoredInterfaces {
				if matchesPattern(iface.Name, configured) {
					result = append(result, iface)
					break
				}
			}
		}
		return result, nil
	}

	// Auto-detect: monitor default interface + other physical interfaces
	for _, iface := range allInterfaces {
		// Always include default interface
		if iface.Name == defaultIface {
			result = append(result, iface)
			continue
		}

		// Include other physical interfaces (excluding virtual ones)
		if shouldMonitorInterface(iface, c.config.ExcludeInterfaces) {
			result = append(result, iface)
		}

		// Limit to max interfaces to prevent metric explosion
		if len(result) >= maxInterfaces {
			break
		}
	}

	return result, nil
}

// getInterfacesWithCache returns network interfaces with caching.
func (c *Collector) getInterfacesWithCache(ctx context.Context) ([]gopsnet.InterfaceStat, error) {
	// Check cache first
	c.interfacesMutex.RLock()
	if time.Now().Before(c.interfacesCacheExp) && len(c.cachedInterfaces) > 0 {
		result := c.cachedInterfaces
		c.interfacesMutex.RUnlock()
		c.logger.Debug("using cached network interfaces", "count", len(result))
		return result, nil
	}
	c.interfacesMutex.RUnlock()

	// Need to refresh cache
	c.interfacesMutex.Lock()
	defer c.interfacesMutex.Unlock()

	// Double-check pattern
	if time.Now().Before(c.interfacesCacheExp) && len(c.cachedInterfaces) > 0 {
		return c.cachedInterfaces, nil
	}

	// Get fresh interface list
	interfaces, err := gopsnet.Interfaces()
	if err != nil {
		// Use cached interfaces if available, even if expired
		if len(c.cachedInterfaces) > 0 {
			c.logger.Warn("failed to refresh network interfaces, using cached", "error", err)
			return c.cachedInterfaces, nil
		}
		return nil, err
	}

	// Update cache
	c.cachedInterfaces = interfaces
	c.interfacesCacheExp = time.Now().Add(interfaceCacheTTL)

	c.logger.Debug("refreshed network interfaces cache", "count", len(interfaces))
	return interfaces, nil
}

// getDefaultInterfaceWithCache returns the default interface with caching.
func (c *Collector) getDefaultInterfaceWithCache() (string, error) {
	// Check cache first
	c.defaultIfaceMutex.RLock()
	if time.Now().Before(c.defaultIfaceExp) && c.defaultIface != "" {
		result := c.defaultIface
		c.defaultIfaceMutex.RUnlock()
		return result, nil
	}
	c.defaultIfaceMutex.RUnlock()

	// Need to refresh cache
	c.defaultIfaceMutex.Lock()
	defer c.defaultIfaceMutex.Unlock()

	// Double-check pattern
	if time.Now().Before(c.defaultIfaceExp) && c.defaultIface != "" {
		return c.defaultIface, nil
	}

	// Get fresh default interface
	defaultIface, err := getDefaultInterface()
	if err != nil {
		// Use cached value if available, even if expired
		if c.defaultIface != "" {
			c.logger.Warn("failed to refresh default interface, using cached", "error", err)
			return c.defaultIface, nil
		}
		return "", err
	}

	// Update cache
	c.defaultIface = defaultIface
	c.defaultIfaceExp = time.Now().Add(defaultGatewayCacheTTL)

	c.logger.Debug("refreshed default interface cache", "interface", defaultIface)
	return defaultIface, nil
}

// HealthCheck performs a health check of the network collector.
func (c *Collector) HealthCheck(ctx context.Context) error {
	// Simple health check - try to get interfaces
	_, err := gopsnet.Interfaces()
	if err != nil {
		return fmt.Errorf("network collector health check failed: %w", err)
	}
	return nil
}

// Close performs any necessary cleanup.
func (c *Collector) Close() error {
	c.logger.Debug("network collector closed")
	return nil
}

// Verify interface compliance at compile time.
var (
	_ metrics.Collector     = (*Collector)(nil)
	_ metrics.HealthChecker = (*Collector)(nil)
)
