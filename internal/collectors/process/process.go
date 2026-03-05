// Package process provides process monitoring for the Netwarden agent.
package process

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"netwarden/internal/config"
	"netwarden/internal/metrics"
)

// ProcessToMonitor represents a process configuration from the API.
type ProcessToMonitor struct {
	AppName     string `json:"app_name"`
	DisplayName string `json:"display_name"`
	ProcessName string `json:"process_name"`
	Enabled     bool   `json:"enabled"`
}

// ProcessStats holds statistics for a running process.
type ProcessStats struct {
	PID        int
	CPUPercent float64
	MemoryMB   float64
}

// processCache provides caching for process configurations.
type processCache struct {
	processes []ProcessToMonitor
	cachedAt  time.Time
	ttl       time.Duration
	mutex     sync.RWMutex
}

// newProcessCache creates a new process cache with 5-minute TTL.
func newProcessCache() *processCache {
	return &processCache{
		ttl:       5 * time.Minute,
		processes: make([]ProcessToMonitor, 0),
	}
}

// get retrieves cached processes if they're still valid.
func (c *processCache) get() ([]ProcessToMonitor, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if time.Since(c.cachedAt) > c.ttl {
		return nil, false
	}
	return c.processes, true
}

// set stores processes in the cache.
func (c *processCache) set(processes []ProcessToMonitor) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.processes = processes
	c.cachedAt = time.Now()
}

// Collector implements metrics.Collector for process metrics.
type Collector struct {
	config     config.ProcessConfig
	hostname   string
	logger     *slog.Logger
	cache      *processCache
	httpClient *http.Client
	apiKey     string
	serverURL  string
}

// CollectorOption configures the process collector.
type CollectorOption func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) CollectorOption {
	return func(c *Collector) {
		c.logger = logger
	}
}

// NewCollector creates a new process collector.
func NewCollector(cfg config.ProcessConfig, hostname string, apiKey string, serverURL string, opts ...CollectorOption) *Collector {
	if serverURL == "" {
		serverURL = "https://api.netwarden.com"
	}
	serverURL = strings.TrimRight(serverURL, "/")

	collector := &Collector{
		config:    cfg,
		hostname:  hostname,
		logger:    slog.Default().With("component", "process_collector"),
		cache:     newProcessCache(),
		apiKey:    apiKey,
		serverURL: serverURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(collector)
	}

	// Fetch initial configuration
	if cfg.EnableProcessMonitoring {
		if err := collector.fetchProcessConfig(context.Background()); err != nil {
			collector.logger.Warn("failed to fetch initial process config", "error", err)
		}
	}

	return collector
}

// fetchProcessConfig fetches the process configuration from the API.
func (c *Collector) fetchProcessConfig(ctx context.Context) error {
	endpoint := c.config.ConfigEndpoint
	if endpoint == "" {
		endpoint = "/agent/processes" // Fix: correct endpoint path
	}

	url := c.serverURL + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "Netwarden-Agent/1.0.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Fix: ResponseBuilder wraps responses in {success: true, data: {...}}
	var apiResponse struct {
		Success bool `json:"success"`
		Data    struct {
			Processes []ProcessToMonitor `json:"processes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !apiResponse.Success {
		return fmt.Errorf("API returned success=false")
	}

	// Validate that processes list is not nil (defensive programming)
	if apiResponse.Data.Processes == nil {
		return fmt.Errorf("API returned nil processes list")
	}

	c.cache.set(apiResponse.Data.Processes)
	c.logger.Info("fetched process configuration", "count", len(apiResponse.Data.Processes))

	return nil
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "process"
}

// Enabled returns whether the collector is enabled.
func (c *Collector) Enabled() bool {
	return c.config.EnableProcessMonitoring
}

// Collect gathers process metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !c.config.EnableProcessMonitoring {
		return nil, nil
	}

	var collected []metrics.Metric
	timestamp := time.Now()

	// Get processes to monitor (fetch new config if cache expired)
	processes, cached := c.cache.get()
	if !cached {
		if err := c.fetchProcessConfig(ctx); err != nil {
			c.logger.Warn("failed to refresh process config", "error", err)
			// Continue with stale cache if available
			processes, _ = c.cache.get()
		}
	}

	if len(processes) == 0 {
		return collected, nil
	}

	// Check each configured process
	for _, proc := range processes {
		if !proc.Enabled {
			continue
		}

		// Check if process is running
		stats := c.getProcessStats(proc.ProcessName)

		// Process up/down metric
		isUp := float64(0)
		if stats != nil {
			isUp = 1
		}

		metricName := "process_up_" + strings.ReplaceAll(strings.ToLower(proc.ProcessName), " ", "_")

		collected = append(collected, metrics.Metric{
			Name:      metricName,
			Value:     isUp,
			Timestamp: timestamp,
			Labels: map[string]string{
				"host":         c.hostname,
				"app_name":     proc.AppName,
				"display_name": proc.DisplayName,
				"process_name": proc.ProcessName,
			},
		})

		// If process is running, collect additional stats
		if stats != nil {
			// CPU usage
			collected = append(collected, metrics.Metric{
				Name:      "process_cpu_percent_" + strings.ReplaceAll(strings.ToLower(proc.ProcessName), " ", "_"),
				Value:     stats.CPUPercent,
				Timestamp: timestamp,
				Labels: map[string]string{
					"host":         c.hostname,
					"app_name":     proc.AppName,
					"display_name": proc.DisplayName,
					"process_name": proc.ProcessName,
				},
			})

			// Memory usage
			collected = append(collected, metrics.Metric{
				Name:      "process_memory_mb_" + strings.ReplaceAll(strings.ToLower(proc.ProcessName), " ", "_"),
				Value:     stats.MemoryMB,
				Timestamp: timestamp,
				Labels: map[string]string{
					"host":         c.hostname,
					"app_name":     proc.AppName,
					"display_name": proc.DisplayName,
					"process_name": proc.ProcessName,
				},
			})

			// Process PID
			collected = append(collected, metrics.Metric{
				Name:      "process_pid_" + strings.ReplaceAll(strings.ToLower(proc.ProcessName), " ", "_"),
				Value:     float64(stats.PID),
				Timestamp: timestamp,
				Labels: map[string]string{
					"host":         c.hostname,
					"app_name":     proc.AppName,
					"display_name": proc.DisplayName,
					"process_name": proc.ProcessName,
				},
			})
		}
	}

	return collected, nil
}

// getProcessStats is implemented in process_unix.go and process_windows.go
// based on the target operating system.

// readProcStats is implemented in process_unix.go and process_windows.go
// based on the target operating system.

// HealthCheck performs a health check.
func (c *Collector) HealthCheck(ctx context.Context) error {
	if !c.config.EnableProcessMonitoring {
		return nil
	}

	// Try to fetch config as health check
	if err := c.fetchProcessConfig(ctx); err != nil {
		return fmt.Errorf("failed to fetch process config: %w", err)
	}

	return nil
}

// Close cleans up the collector.
func (c *Collector) Close() error {
	// Nothing to close
	return nil
}
