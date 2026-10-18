// Package process monitors the application processes an operator configured
// in the Netwarden UI: whether each is running, and its CPU and memory use.
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

	"github.com/NetwardenHQ/agent/internal/config"
	sharedhttp "github.com/NetwardenHQ/agent/internal/http"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

// ProcessToMonitor is one entry of the process list served by the API.
type ProcessToMonitor struct {
	AppName     string `json:"app_name"`
	DisplayName string `json:"display_name"`
	ProcessName string `json:"process_name"`
	Enabled     bool   `json:"enabled"`
}

// ProcessStats is a running process's resource use at one instant.
type ProcessStats struct {
	PID int
	// CPUTime is the cumulative user+system CPU time consumed since the
	// process started. Utilization is derived by the collector from the
	// change between two cycles.
	CPUTime  time.Duration
	MemoryMB float64
	// CPUKnown / MemoryKnown say the figure was actually read. A process can
	// be found and still not be readable (permissions, or it exited
	// mid-read); its unknown figures are omitted, never sent as 0.
	CPUKnown    bool
	MemoryKnown bool
}

// cpuSample remembers a process's CPU time at the previous cycle so the next
// one can turn it into a percentage.
type cpuSample struct {
	pid     int
	cpuTime time.Duration
	at      time.Time
}

// Collector implements metrics.Collector for process metrics.
type Collector struct {
	config     config.ProcessConfig
	hostname   string
	logger     *slog.Logger
	httpClient *http.Client
	apiKey     string
	serverURL  string
	userAgent  string

	mu           sync.Mutex
	processes    []ProcessToMonitor
	fetchedAt    time.Time // last successful fetch
	nextFetch    time.Time // when the list is next refreshed; zero = now
	lastFetchErr error
	prev         map[string]cpuSample // keyed by process name
}

// CollectorOption configures the process collector.
type CollectorOption func(*Collector)

// WithLogger sets the logger for the collector.
func WithLogger(logger *slog.Logger) CollectorOption {
	return func(c *Collector) {
		c.logger = logger
	}
}

// WithUserAgent sets the User-Agent sent when fetching the process list.
func WithUserAgent(ua string) CollectorOption {
	return func(c *Collector) {
		if ua != "" {
			c.userAgent = ua
		}
	}
}

// NewCollector creates a new process collector. The process list is fetched
// on the first Collect, not here: construction must not block on the network.
func NewCollector(cfg config.ProcessConfig, hostname string, apiKey string, serverURL string, opts ...CollectorOption) *Collector {
	if serverURL == "" {
		serverURL = config.DefaultServerURL
	}

	c := &Collector{
		config:     cfg,
		hostname:   hostname,
		logger:     slog.Default().With("component", "process_collector"),
		apiKey:     apiKey,
		serverURL:  strings.TrimRight(serverURL, "/"),
		userAgent:  "Netwarden-Agent",
		httpClient: sharedhttp.GetClientWithTimeout(10 * time.Second),
		prev:       make(map[string]cpuSample),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// fetchRetryDelay is how soon a failed process-list fetch is retried. The
// collector runs every reporting interval (as little as ten seconds), so
// without a delay an API outage would draw a request from every agent on
// every cycle.
const fetchRetryDelay = time.Minute

// processList returns the configured processes, refreshing them from the API
// every ConfigFetchInterval. A failed refresh keeps the previous list and is
// retried after fetchRetryDelay (or ConfigFetchInterval, if shorter).
func (c *Collector) processList(ctx context.Context) []ProcessToMonitor {
	c.mu.Lock()
	stale := !time.Now().Before(c.nextFetch)
	c.mu.Unlock()

	if stale {
		if err := c.fetchProcessConfig(ctx); err != nil {
			c.logger.Warn("failed to refresh process config", "error", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.processes
}

// fetchProcessConfig fetches the process list from the API.
func (c *Collector) fetchProcessConfig(ctx context.Context) error {
	endpoint := c.config.ConfigEndpoint
	if endpoint == "" {
		endpoint = "/agent/processes"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return c.recordFetch(nil, fmt.Errorf("failed to fetch config: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return c.recordFetch(nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body))))
	}

	// The API wraps every response as {success, data}.
	var apiResponse struct {
		Success bool `json:"success"`
		Data    struct {
			Processes []ProcessToMonitor `json:"processes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return c.recordFetch(nil, fmt.Errorf("failed to decode response: %w", err))
	}
	if !apiResponse.Success {
		return c.recordFetch(nil, fmt.Errorf("API returned success=false"))
	}
	if apiResponse.Data.Processes == nil {
		return c.recordFetch(nil, fmt.Errorf("API returned no processes list"))
	}

	c.logger.Info("fetched process configuration", "count", len(apiResponse.Data.Processes))
	return c.recordFetch(apiResponse.Data.Processes, nil)
}

// recordFetch stores the outcome of a fetch. On success the list and its
// timestamp are replaced; on failure only the error is kept, so a transient
// outage does not blank the list. It returns err for convenience.
func (c *Collector) recordFetch(processes []ProcessToMonitor, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastFetchErr = err
	now := time.Now()
	if err == nil {
		c.processes = processes
		c.fetchedAt = now
		c.nextFetch = now.Add(c.config.ConfigFetchInterval)
		return nil
	}
	retry := fetchRetryDelay
	if iv := c.config.ConfigFetchInterval; iv > 0 && iv < retry {
		retry = iv
	}
	c.nextFetch = now.Add(retry)
	return err
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

	processes := c.processList(ctx)
	if len(processes) == 0 {
		return nil, nil
	}

	timestamp := time.Now()
	var collected []metrics.Metric

	for _, proc := range processes {
		if !proc.Enabled {
			continue
		}

		// An empty name is a substring of every command line and would
		// "find" whatever process sorts first.
		if strings.TrimSpace(proc.ProcessName) == "" {
			c.logger.Debug("skipping process entry with an empty process_name", "app_name", proc.AppName)
			continue
		}

		stats := c.getProcessStats(proc.ProcessName)
		if stats == nil {
			c.forget(proc.ProcessName)
		}
		collected = append(collected, c.processMetrics(proc, stats, timestamp)...)
	}

	return collected, nil
}

// processMetrics turns one monitored process's stats (nil = not running)
// into series.
func (c *Collector) processMetrics(proc ProcessToMonitor, stats *ProcessStats, timestamp time.Time) []metrics.Metric {
	labels := map[string]string{
		"host":         c.hostname,
		"app_name":     proc.AppName,
		"display_name": proc.DisplayName,
		"process_name": proc.ProcessName,
	}
	suffix := metricSuffix(proc.ProcessName)
	gauge := func(name string, value float64) metrics.Metric {
		return metrics.Metric{
			Name:      name + suffix,
			Type:      metrics.MetricTypeGauge,
			Value:     value,
			Timestamp: timestamp,
			Labels:    labels,
		}
	}

	if stats == nil {
		return []metrics.Metric{gauge("process_up_", 0)}
	}

	out := []metrics.Metric{gauge("process_up_", 1), gauge("process_pid_", float64(stats.PID))}
	if stats.MemoryKnown {
		out = append(out, gauge("process_memory_mb_", stats.MemoryMB))
	}
	// Utilization needs two observations of the same process. The first
	// cycle after a (re)start has none, so it reports no percentage rather
	// than a made-up one.
	if percent, ok := c.observe(proc.ProcessName, stats, timestamp); ok {
		out = append(out, gauge("process_cpu_percent_", percent))
	}
	return out
}

// observe records a CPU observation and returns the utilization since the
// previous one. Unknown CPU time drops the baseline instead of storing a 0:
// a 0 baseline would make the next good read look like the process's whole
// lifetime of CPU spent in one interval.
func (c *Collector) observe(name string, stats *ProcessStats, now time.Time) (float64, bool) {
	if !stats.CPUKnown {
		c.forget(name)
		return 0, false
	}
	return c.cpuPercent(name, stats, now)
}

// cpuPercent turns cumulative CPU time into utilization over the time since
// the previous observation of the same PID. 100 means one full core.
func (c *Collector) cpuPercent(name string, stats *ProcessStats, now time.Time) (float64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev, seen := c.prev[name]
	c.prev[name] = cpuSample{pid: stats.PID, cpuTime: stats.CPUTime, at: now}

	if !seen || prev.pid != stats.PID {
		return 0, false
	}
	elapsed := now.Sub(prev.at)
	if elapsed <= 0 {
		return 0, false
	}
	used := stats.CPUTime - prev.cpuTime
	if used < 0 {
		return 0, false
	}
	return float64(used) / float64(elapsed) * 100, true
}

// forget drops the CPU sample for a process that is no longer running.
func (c *Collector) forget(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.prev, name)
}

// metricSuffix derives the per-process metric name suffix the platform keys on.
func metricSuffix(processName string) string {
	return strings.ReplaceAll(strings.ToLower(processName), " ", "_")
}

// HealthCheck reports the outcome of the most recent process-list fetch. It
// makes no request of its own: the agent runs health checks at startup, and
// a fleet restarting at once must not all hit the API at the same instant.
func (c *Collector) HealthCheck(ctx context.Context) error {
	if !c.config.EnableProcessMonitoring {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastFetchErr != nil {
		return fmt.Errorf("process config fetch failed: %w", c.lastFetchErr)
	}
	return nil
}

// Close cleans up the collector.
func (c *Collector) Close() error {
	return nil
}

// Verify interface compliance at compile time.
var (
	_ metrics.Collector     = (*Collector)(nil)
	_ metrics.HealthChecker = (*Collector)(nil)
)
