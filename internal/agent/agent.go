// Copyright 2024-2025 Netwarden
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package agent provides the main Netwarden agent implementation
// that coordinates metric collection, processing, and transmission.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"netwarden/internal/cache"
	"netwarden/internal/collectors/container"
	"netwarden/internal/collectors/cpu"
	"netwarden/internal/collectors/disk"
	"netwarden/internal/collectors/memory"
	"netwarden/internal/collectors/mysql"
	"netwarden/internal/collectors/network"
	"netwarden/internal/collectors/postgresql"
	"netwarden/internal/collectors/process"
	"netwarden/internal/collectors/system"
	"netwarden/internal/config"
	sharedhttp "netwarden/internal/http"
	"netwarden/internal/metrics"
	"netwarden/internal/registry"
)

// Agent represents the main Netwarden agent.
type Agent struct {
	config   *config.Config
	logger   *slog.Logger
	registry metrics.Registry
	hostname string
	version  string

	// Control channels
	stopChan chan struct{}
	stopOnce sync.Once

	// Metrics transmission
	transmitter MetricTransmitter

	// Phase 4 optimizations
	deltaTracker *metrics.DeltaTracker
	batchSize    int

	// Cache cleanup
	cacheCleanupStop chan struct{}

	// Connection tracking
	lastTransmissionFailed bool
	consecutiveFailures    int
	mu                     sync.RWMutex

	// Dynamic reporting interval from backend
	reportingInterval time.Duration
	httpClient        *http.Client // For config fetching

	// Background update checks
	updateCheckStop chan struct{}
}

// MetricTransmitter defines the interface for transmitting metrics to the server.
type MetricTransmitter interface {
	Send(ctx context.Context, metrics []metrics.Metric) error
	Close() error
}

// New creates a new Netwarden agent instance.
func New(cfg *config.Config, logger *slog.Logger, version string) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Get hostname from config or system
	var hostname string
	if cfg.Hostname != "" {
		hostname = cfg.Hostname
		logger.Info("using custom hostname from config", "hostname", hostname)
	} else {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			hostname = "unknown"
			logger.Warn("failed to get hostname", "error", err)
		}
	}

	// Create registry
	reg := registry.NewRegistry(logger.With("component", "registry"))

	// Create transmitter with hostname and version
	transmitter, err := NewHTTPTransmitter(cfg, hostname, version, logger.With("component", "transmitter"))
	if err != nil {
		return nil, fmt.Errorf("failed to create transmitter: %w", err)
	}

	// Initialize Phase 4 optimizations
	deltaTracker := metrics.NewDeltaTracker(metrics.DeltaConfig{
		Threshold: 1.0,             // 1% change threshold
		MaxAge:    5 * time.Minute, // Force send after 5 minutes
		Enabled:   true,
		Logger:    logger.With("component", "delta"),
	})

	// Use simple fixed batch size instead of adaptive batching
	batchSize := 500

	// Start global cache cleanup to prevent memory leaks
	cacheCleanupStop := cache.StartGlobalCleanup(5 * time.Minute)

	agent := &Agent{
		config:            cfg,
		logger:            logger,
		registry:          reg,
		hostname:          hostname,
		version:           version,
		stopChan:          make(chan struct{}),
		transmitter:       transmitter,
		deltaTracker:      deltaTracker,
		batchSize:         batchSize,
		cacheCleanupStop:  cacheCleanupStop,
		reportingInterval: 60 * time.Second,       // Default to 60 seconds
		httpClient:        sharedhttp.GetClient(), // Use shared HTTP client
		updateCheckStop:   make(chan struct{}),
	}

	// Register all collectors
	if err := agent.registerCollectors(); err != nil {
		return nil, fmt.Errorf("failed to register collectors: %w", err)
	}

	logger.Info("Netwarden agent created successfully",
		"hostname", hostname,
		"collectors", reg.ListCollectors())

	return agent, nil
}

// registerCollectors registers all configured collectors with the registry.
func (a *Agent) registerCollectors() error {
	collectorLogger := a.logger.With("component", "collector")

	// CPU collector (always enabled with defaults)
	if a.config.Collectors.CPU {
		cpuCollector := cpu.NewCollector(
			nil, // Use defaults
			a.hostname,
			cpu.WithLogger(collectorLogger.With("type", "cpu")),
		)
		if err := a.registry.Register(cpuCollector); err != nil {
			return fmt.Errorf("failed to register CPU collector: %w", err)
		}
	}

	// Memory collector (always enabled with defaults)
	if a.config.Collectors.Memory {
		memoryCollector := memory.NewCollector(
			nil, // Use defaults
			a.hostname,
			memory.WithLogger(collectorLogger.With("type", "memory")),
		)
		if err := a.registry.Register(memoryCollector); err != nil {
			return fmt.Errorf("failed to register memory collector: %w", err)
		}
	}

	// System collector (enabled by default for OS info and uptime)
	if a.config.Collectors.System {
		systemCollector := system.NewCollector(
			config.SystemConfig{
				Enabled:       true,
				CollectUptime: true,
			},
			a.hostname,
			system.WithLogger(collectorLogger.With("type", "system")),
		)
		if err := a.registry.Register(systemCollector); err != nil {
			return fmt.Errorf("failed to register system collector: %w", err)
		}
	}

	// Disk collector (enabled for disk usage monitoring)
	if a.config.Collectors.Disk {
		diskCollector := disk.NewCollector(
			a.hostname,
			disk.WithLogger(collectorLogger.With("type", "disk")),
		)
		if err := a.registry.Register(diskCollector); err != nil {
			return fmt.Errorf("failed to register disk collector: %w", err)
		}
		a.logger.Info("registered disk collector")
	}

	// Network collector (enabled for network interface monitoring)
	if a.config.Collectors.Network {
		networkCollector := network.NewCollector(
			a.config.Network,
			a.hostname,
			network.WithLogger(collectorLogger.With("type", "network")),
		)
		if err := a.registry.Register(networkCollector); err != nil {
			return fmt.Errorf("failed to register network collector: %w", err)
		}
		a.logger.Info("registered network collector")
	}

	// Container collector (enabled when configured)
	if a.config.Collectors.Container {
		containerCollector := container.NewCollector(
			a.config.Container,
			a.hostname,
			container.WithLogger(collectorLogger.With("type", "container")),
		)
		if err := a.registry.Register(containerCollector); err != nil {
			return fmt.Errorf("failed to register container collector: %w", err)
		}
		a.logger.Info("registered container collector")
	}

	// VM collector (Linux only)
	if err := a.registerVMCollector(collectorLogger); err != nil {
		return err
	}

	// MySQL collector (auto-detects running MySQL/MariaDB)
	mysqlCollector := mysql.NewCollector(
		a.config.Database,
		a.hostname,
		mysql.WithLogger(collectorLogger.With("type", "mysql")),
	)
	// Only register if explicitly enabled OR if auto-detected and connected
	if a.config.Database.EnableMySQL || mysqlCollector.Enabled() {
		if err := a.registry.Register(mysqlCollector); err != nil {
			// Don't fail if MySQL collector can't be registered (process might not be running)
			a.logger.Debug("MySQL collector not registered", "error", err)
		} else {
			a.logger.Info("registered MySQL collector")
		}
	}

	// PostgreSQL collector (auto-detects running PostgreSQL)
	postgresqlCollector := postgresql.NewCollector(
		a.config.Database,
		a.hostname,
		postgresql.WithLogger(collectorLogger.With("type", "postgresql")),
	)
	// Only register if explicitly enabled OR if auto-detected and connected
	if a.config.Database.EnablePostgreSQL || postgresqlCollector.Enabled() {
		if err := a.registry.Register(postgresqlCollector); err != nil {
			// Don't fail if PostgreSQL collector can't be registered (process might not be running)
			a.logger.Debug("PostgreSQL collector not registered", "error", err)
		} else {
			a.logger.Info("registered PostgreSQL collector")
		}
	}

	// Process collector (monitors configured application processes)
	if a.config.Process.EnableProcessMonitoring {
		processCollector := process.NewCollector(
			a.config.Process,
			a.hostname,
			a.config.APIKey,
			a.config.ServerURL,
			process.WithLogger(collectorLogger.With("type", "process")),
		)
		if err := a.registry.Register(processCollector); err != nil {
			a.logger.Warn("failed to register process collector", "error", err)
		} else {
			a.logger.Info("registered process collector")
		}
	}

	return nil
}

// FetchRemoteConfig retrieves the reporting interval and other config from backend
func (a *Agent) FetchRemoteConfig(ctx context.Context) error {
	// Create context with timeout for the request
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET",
		a.config.ServerURL+"/agent/config", nil)
	if err != nil {
		return fmt.Errorf("creating config request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+a.config.APIKey)
	req.Header.Set("User-Agent", fmt.Sprintf("Netwarden-Agent/%s", a.version))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("config fetch timeout after 10s")
		}
		return fmt.Errorf("fetching config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config fetch failed: status %d", resp.StatusCode)
	}

	// ResponseBuilder wraps responses in {success: true, data: {...}}
	var apiResponse struct {
		Success bool `json:"success"`
		Data    struct {
			ReportingInterval int    `json:"reporting_interval"`
			TenantID          string `json:"tenant_id"`
			PlanID            string `json:"plan_id"`
			Features          struct {
				MetricsEnabled   bool `json:"metrics_enabled"`
				ProcessesEnabled bool `json:"processes_enabled"`
			} `json:"features"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return fmt.Errorf("decoding config: %w", err)
	}

	if !apiResponse.Success {
		return fmt.Errorf("API returned success=false")
	}

	// Validate response has required fields
	if apiResponse.Data.ReportingInterval <= 0 {
		return fmt.Errorf("invalid reporting interval: %d", apiResponse.Data.ReportingInterval)
	}

	// Update agent's reporting interval with validation and proper locking
	a.mu.Lock()
	oldInterval := a.reportingInterval
	a.mu.Unlock()

	newInterval := time.Duration(apiResponse.Data.ReportingInterval) * time.Second

	// Sanity check: interval should be between 10 seconds and 1 hour
	if newInterval < 10*time.Second || newInterval > 1*time.Hour {
		a.logger.Warn("Received invalid interval, using default",
			"received_interval", newInterval.String(),
			"default_interval", oldInterval.String())
		return fmt.Errorf("invalid interval received: %v", newInterval)
	}

	// Lock only for the write operation
	a.mu.Lock()
	a.reportingInterval = newInterval
	a.mu.Unlock()

	if oldInterval != newInterval {
		a.logger.Info("Updated reporting interval",
			"old_interval", oldInterval.String(),
			"new_interval", newInterval.String(),
			"plan_id", apiResponse.Data.PlanID)
	}

	return nil
}

// testConnection performs a startup connectivity check against the server.
// Logs the result but never blocks agent startup.
func (a *Agent) testConnection(ctx context.Context) {
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := a.config.ServerURL + "/agent/config"
	req, err := http.NewRequestWithContext(testCtx, "GET", url, nil)
	if err != nil {
		a.logger.Warn("failed to create connection test request", "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.config.APIKey)
	req.Header.Set("User-Agent", "Netwarden-Agent/"+a.version)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Warn("server connection test failed",
			"server_url", a.config.ServerURL,
			"error", err,
			"hint", "check server_url, network connectivity, and TLS settings")
		return
	}
	resp.Body.Close()

	switch {
	case resp.StatusCode == 401:
		a.logger.Error("server reachable but authentication failed",
			"server_url", a.config.ServerURL,
			"hint", "check tenant_id and api_key in config")
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		a.logger.Info("connected to Netwarden server", "server_url", a.config.ServerURL)
	default:
		a.logger.Warn("server returned unexpected status",
			"server_url", a.config.ServerURL,
			"status", resp.StatusCode)
	}
}

// Run starts the agent's main collection and transmission loop.
func (a *Agent) Run(ctx context.Context) error {
	// Test server connectivity on startup (non-blocking)
	a.testConnection(ctx)

	// Add jitter to initial config fetch to prevent thundering herd (0-20 seconds)
	// This prevents all agents from hitting the API simultaneously during mass deployments
	initialJitter := time.Duration(rand.Intn(20)) * time.Second
	time.Sleep(initialJitter)

	// Fetch initial config from backend
	if err := a.FetchRemoteConfig(ctx); err != nil {
		a.mu.RLock()
		defaultInterval := a.reportingInterval.String()
		a.mu.RUnlock()
		// Log at ERROR level for initial failure as it's more important
		a.logger.Error("Failed to fetch initial remote config on startup",
			"error", err,
			"hostname", a.hostname,
			"tenant_id", a.config.TenantID,
			"default_interval", defaultInterval,
			"next_retry", "1 hour")
		// Continue with default interval
	}

	a.mu.RLock()
	currentInterval := a.reportingInterval
	a.mu.RUnlock()

	a.logger.Info("starting Netwarden agent",
		"collection_interval", currentInterval.String(),
		"buffer_size", a.config.Buffer.MaxSize)

	// Perform initial health check
	if err := a.performHealthCheck(ctx); err != nil {
		a.logger.Warn("initial health check failed", "error", err)
	}

	// Create ticker for collection intervals using dynamic interval
	a.mu.RLock()
	ticker := time.NewTicker(a.reportingInterval)
	a.mu.RUnlock()
	// Use closure so defer stops the CURRENT ticker, not the original one
	defer func() { ticker.Stop() }()

	// Create ticker for delta tracker cleanup (every hour)
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	// Create ticker for config refresh with jitter to prevent thundering herd
	// Random interval between 50-70 minutes
	jitterMinutes := 50 + rand.Intn(20)
	configRefreshTicker := time.NewTicker(time.Duration(jitterMinutes) * time.Minute)
	defer configRefreshTicker.Stop()

	// Start background update check goroutine
	go a.runBackgroundUpdateChecks(ctx)

	// Main collection loop
	for {
		select {
		case <-ctx.Done():
			a.logger.Info("context cancelled, stopping agent")
			return ctx.Err()
		case <-cleanupTicker.C:
			// Periodic cleanup of delta tracker to prevent memory leaks
			removed := a.deltaTracker.Cleanup(24 * time.Hour)
			if removed > 0 {
				a.logger.Debug("Delta tracker cleanup completed", "removed_metrics", removed)
			}

		case <-configRefreshTicker.C:
			// Refresh config periodically to pick up plan changes
			a.mu.RLock()
			oldInterval := a.reportingInterval
			a.mu.RUnlock()

			if err := a.FetchRemoteConfig(ctx); err != nil {
				// Log at ERROR level for better observability
				a.logger.Error("Failed to fetch remote config during periodic refresh",
					"error", err,
					"hostname", a.hostname,
					"tenant_id", a.config.TenantID,
					"current_interval", oldInterval.String(),
					"will_retry_in", "1 hour")
				// Continue with existing interval
			} else {
				// Check if interval changed
				a.mu.RLock()
				newInterval := a.reportingInterval
				a.mu.RUnlock()

				if oldInterval != newInterval {
					// Fix: Stop old ticker and create new one (Reset doesn't change duration in Go < 1.23)
					// IMPORTANT: Keep reference to old ticker to stop it after creating new one
					oldTicker := ticker
					ticker = time.NewTicker(newInterval)
					oldTicker.Stop() // Stop old ticker after new one is created to avoid race
					a.logger.Info("Collection ticker recreated with new interval",
						"old_interval", oldInterval.String(),
						"new_interval", newInterval.String())
				}
			}

		case <-a.stopChan:
			a.logger.Info("stop signal received, stopping agent")
			return nil

		case <-ticker.C:
			if err := a.collectAndTransmit(ctx); err != nil {
				a.logger.Error("collection and transmission failed", "error", err)
				// Continue running despite errors
			}
		}
	}
}

// runBackgroundUpdateChecks runs system update checks in the background
// to prevent blocking the main metric collection cycle.
func (a *Agent) runBackgroundUpdateChecks(ctx context.Context) {
	a.logger.Info("starting background update check goroutine")

	// Initial delay of 30 seconds to let the agent stabilize
	select {
	case <-time.After(30 * time.Second):
		// Continue to first check
	case <-ctx.Done():
		return
	case <-a.updateCheckStop:
		return
	}

	// Perform initial update check
	a.performUpdateCheck(ctx)

	// Create ticker for periodic checks (every 6 hours)
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("background update check stopped: context cancelled")
			return
		case <-a.updateCheckStop:
			a.logger.Info("background update check stopped: stop signal received")
			return
		case <-ticker.C:
			a.performUpdateCheck(ctx)
		}
	}
}

// performUpdateCheck executes the system update check and caches results.
func (a *Agent) performUpdateCheck(ctx context.Context) {
	// Only perform update checks on supported platforms
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		return
	}

	a.logger.Debug("performing background system update check")

	// Get the system collector from registry
	systemCollector, err := a.getSystemCollector()
	if err != nil {
		a.logger.Warn("system collector not available for update checks", "error", err)
		return
	}

	// Use the cache system to store results
	cacheKey := fmt.Sprintf("system:updates:%s", a.hostname)

	// Get available updates count (platform-specific)
	updateCount, err := systemCollector.GetAvailableUpdates(ctx)
	if err != nil {
		a.logger.Warn("background update check failed", "error", err)
		return
	}

	// Get security updates count
	securityCount, err := systemCollector.GetSecurityUpdates(ctx)
	if err != nil {
		a.logger.Warn("background security update check failed", "error", err)
		// Continue with general updates even if security check fails
		securityCount = 0
	}

	// Store in cache with 6-hour expiration (aligns with check interval)
	updateInfo := map[string]interface{}{
		"count":          updateCount,
		"security_count": securityCount,
		"timestamp":      time.Now(),
	}
	cache.Set(cacheKey, updateInfo, 6*time.Hour)

	a.logger.Info("background update check completed",
		"updates_available", updateCount,
		"security_updates", securityCount)
}

// getSystemCollector retrieves the system collector from the registry.
func (a *Agent) getSystemCollector() (*system.Collector, error) {
	collectors := a.registry.ListCollectors()
	for _, name := range collectors {
		if name == "system" {
			// Get the collector interface
			collector := a.registry.GetCollector("system")
			if collector == nil {
				return nil, fmt.Errorf("system collector not found in registry")
			}
			// Type assert to system.Collector
			if sysCollector, ok := collector.(*system.Collector); ok {
				return sysCollector, nil
			}
			return nil, fmt.Errorf("system collector type assertion failed")
		}
	}
	return nil, fmt.Errorf("system collector not registered")
}

// collectAndTransmit performs a single collection cycle and transmits metrics.
func (a *Agent) collectAndTransmit(ctx context.Context) error {
	// Collect metrics from all registered collectors
	collectedMetrics, err := a.registry.CollectAll(ctx)

	// Log partial collection failures but continue if we have any metrics
	if err != nil {
		a.logger.Warn("partial collection failure", "error", err)
		// Don't return error here - continue with metrics we did collect
	}

	// Only skip transmission if we have no metrics at all
	if len(collectedMetrics) == 0 {
		if err != nil {
			// No metrics AND errors - this is a complete failure
			return fmt.Errorf("metric collection completely failed: %w", err)
		}
		// No metrics but no error either (all collectors disabled?)
		return nil
	}

	// Transmit metrics in batches (even if some collectors failed)
	if err := a.transmitMetrics(ctx, collectedMetrics); err != nil {
		// Track failure
		a.mu.Lock()
		a.consecutiveFailures++
		a.lastTransmissionFailed = true
		a.mu.Unlock()

		return fmt.Errorf("metric transmission failed: %w", err)
	}

	// Check if we recovered from previous failures
	a.mu.Lock()
	wasFailedBefore := a.lastTransmissionFailed
	previousFailures := a.consecutiveFailures
	if wasFailedBefore {
		// Log recovery message at INFO level so it's visible
		a.logger.Info("CONNECTION RESTORED: Successfully reconnected to Netwarden backend and resumed metric transmission",
			"previous_consecutive_failures", previousFailures,
			"downtime_estimate", fmt.Sprintf("~%d minutes", previousFailures))
		a.lastTransmissionFailed = false
		a.consecutiveFailures = 0
	}
	a.mu.Unlock()

	return nil
}

// transmitMetrics sends metrics to the server using Phase 4 optimizations.
func (a *Agent) transmitMetrics(ctx context.Context, allMetrics []metrics.Metric) error {
	a.logger.Debug("starting metric transmission", "total_metrics", len(allMetrics))

	// Phase 4.1: Apply delta compression to filter out unchanged metrics
	filteredMetrics := a.deltaTracker.FilterMetrics(allMetrics)

	a.logger.Debug("delta filtering completed", "total_metrics", len(allMetrics), "filtered_metrics", len(filteredMetrics))

	// Skip transmission if no metrics need to be sent
	if len(filteredMetrics) == 0 {
		a.logger.Debug("no metrics need to be sent after delta filtering")
		return nil
	}

	// Use simple fixed-size batching
	batches := a.createBatches(filteredMetrics, a.batchSize)

	// Transmit each batch
	for i, batch := range batches {
		start := time.Now()
		err := a.transmitter.Send(ctx, batch)
		transmitDuration := time.Since(start)

		if err != nil {
			a.logger.Error("Failed to send batch",
				"batch_index", i,
				"batch_size", len(batch),
				"latency_ms", transmitDuration.Milliseconds(),
				"error", err)
			return fmt.Errorf("failed to send batch %d: %w", i, err)
		}

		a.logger.Debug("Batch sent successfully",
			"batch_index", i,
			"batch_size", len(batch),
			"latency_ms", transmitDuration.Milliseconds())
	}

	return nil
}

// performHealthCheck checks the health of all collectors.
func (a *Agent) performHealthCheck(ctx context.Context) error {
	healthResults := a.registry.HealthCheck(ctx)

	var healthErrors []string
	healthyCount := 0

	for collectorName, err := range healthResults {
		if err != nil {
			healthErrors = append(healthErrors, fmt.Sprintf("%s: %v", collectorName, err))
			a.logger.Warn("collector health check failed", "collector", collectorName, "error", err)
		} else {
			healthyCount++
		}
	}

	totalCollectors := len(healthResults)
	a.logger.Info("health check completed",
		"healthy", healthyCount,
		"total", totalCollectors,
		"failed", len(healthErrors))

	if len(healthErrors) > 0 {
		return fmt.Errorf("health check failures: %v", healthErrors)
	}

	return nil
}

// Stop gracefully stops the agent.
func (a *Agent) Stop() {
	a.stopOnce.Do(func() {
		close(a.stopChan)
	})
}

// Shutdown performs graceful shutdown with timeout.
func (a *Agent) Shutdown(ctx context.Context) error {
	a.logger.Info("shutting down Netwarden agent")

	// Stop the main loop
	a.Stop()

	var shutdownErrors []error

	// Close transmitter
	if err := a.transmitter.Close(); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("transmitter shutdown error: %w", err))
	}

	// Close registry (which closes all collectors)
	if err := a.registry.Close(); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("registry shutdown error: %w", err))
	}

	// Stop cache cleanup
	if a.cacheCleanupStop != nil {
		close(a.cacheCleanupStop)
	}

	// Stop background update checks
	if a.updateCheckStop != nil {
		close(a.updateCheckStop)
	}

	if len(shutdownErrors) > 0 {
		return fmt.Errorf("shutdown errors: %v", shutdownErrors)
	}

	a.logger.Info("Netwarden agent shutdown completed")
	return nil
}

// createBatches creates fixed-size batches from metrics.
func (a *Agent) createBatches(allMetrics []metrics.Metric, batchSize int) [][]metrics.Metric {
	if len(allMetrics) == 0 {
		return nil
	}

	if batchSize <= 0 {
		batchSize = 500 // Default batch size
	}

	var batches [][]metrics.Metric
	for i := 0; i < len(allMetrics); i += batchSize {
		end := i + batchSize
		if end > len(allMetrics) {
			end = len(allMetrics)
		}
		batches = append(batches, allMetrics[i:end])
	}

	return batches
}

// GetStatus returns the current status of the agent.
func (a *Agent) GetStatus(ctx context.Context) map[string]interface{} {
	// Get current reporting interval with proper locking
	a.mu.RLock()
	currentInterval := a.reportingInterval.String()
	a.mu.RUnlock()

	status := map[string]interface{}{
		"hostname":            a.hostname,
		"collection_interval": currentInterval,
		"buffer_size":         a.config.Buffer.MaxSize,
		"collectors":          a.registry.ListCollectors(),
	}

	// Add health check results
	healthResults := a.registry.HealthCheck(ctx)
	healthStatus := make(map[string]string)
	for name, err := range healthResults {
		if err != nil {
			healthStatus[name] = fmt.Sprintf("error: %v", err)
		} else {
			healthStatus[name] = "healthy"
		}
	}
	status["health"] = healthStatus

	return status
}
