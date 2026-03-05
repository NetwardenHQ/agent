// Package agent provides simplified metric transmission to the Netwarden backend.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"netwarden/internal/config"
	sharedhttp "netwarden/internal/http"
	"netwarden/internal/metrics"
	"netwarden/internal/resilience"
)

// apiDataPath is the path for metric submission, appended to the server URL.
const apiDataPath = "/agent/data"

// HTTPTransmitter sends metrics to the Netwarden backend using standard HTTP.
type HTTPTransmitter struct {
	config        *config.Config
	logger        *slog.Logger
	httpClient    *http.Client
	version       string
	hostname      string // Agent hostname for consistent identification
	lastLatencyMs int64  // Last measured latency in milliseconds

	// Recovery mechanism
	consecutiveFailures int
	lastFailure         time.Time
	mu                  sync.RWMutex
}

// NewHTTPTransmitter creates a new HTTP transmitter.
func NewHTTPTransmitter(cfg *config.Config, hostname string, version string, logger *slog.Logger) (MetricTransmitter, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	if hostname == "" {
		hostname = "unknown"
	}
	if version == "" {
		version = "dev"
	}
	if logger == nil {
		logger = slog.Default()
	}

	t := &HTTPTransmitter{
		config:     cfg,
		logger:     logger,
		version:    version,
		hostname:   hostname,
		httpClient: sharedhttp.GetClient(), // Use global client
	}

	return t, nil
}

// clearIdleConnectionsIfNeeded clears idle connections after persistent failures.
func (t *HTTPTransmitter) clearIdleConnectionsIfNeeded() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Clear connections after 5 consecutive failures
	if t.consecutiveFailures >= 5 {
		if t.httpClient != nil {
			// Close idle connections on the global client's transport
			if transport, ok := t.httpClient.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}

		t.logger.Info("cleared idle connections after persistent failures",
			"consecutive_failures", t.consecutiveFailures)

		t.consecutiveFailures = 0
	}
}

// Send transmits metrics to the backend with retry logic and recovery mechanisms.
func (t *HTTPTransmitter) Send(ctx context.Context, metrics []metrics.Metric) error {
	if len(metrics) == 0 {
		t.logger.Debug("no metrics to send")
		return nil
	}

	t.logger.Debug("attempting to send metrics", "count", len(metrics))

	// Check if we should back off due to recent failures
	if t.shouldBackoff() {
		t.logger.Debug("backing off due to recent failures")
		return fmt.Errorf("backing off due to recent transmission failures")
	}

	// Clear idle connections if we've had too many failures
	t.clearIdleConnectionsIfNeeded()

	// Create payload
	payload := t.createPayload(metrics)

	// Marshal to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send with retry
	err = resilience.Retry(ctx, func() error {
		return t.sendRequest(ctx, jsonData, 0) // Start with retry count 0
	})

	// Update failure tracking
	t.updateFailureTracking(err)

	if err != nil {
		t.logger.Warn("failed to send metrics", "error", err, "count", len(metrics))
	} else {
		t.logger.Debug("successfully sent metrics", "count", len(metrics))
	}

	return err
}

// shouldBackoff determines if we should back off from sending due to recent failures.
func (t *HTTPTransmitter) shouldBackoff() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// No backoff if we haven't had many failures
	if t.consecutiveFailures < 3 {
		return false
	}

	// Exponential backoff: 30s, 60s, 120s, 240s, then cap at 300s
	backoffSeconds := 30 * (1 << uint(t.consecutiveFailures-3))
	if backoffSeconds > 300 {
		backoffSeconds = 300
	}

	backoffDuration := time.Duration(backoffSeconds) * time.Second
	return time.Since(t.lastFailure) < backoffDuration
}

// updateFailureTracking updates the failure counters based on the result.
func (t *HTTPTransmitter) updateFailureTracking(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err != nil {
		t.consecutiveFailures++
		t.lastFailure = time.Now()
		t.logger.Warn("transmission failed",
			"consecutive_failures", t.consecutiveFailures,
			"error", err)
	} else {
		// Reset on success
		if t.consecutiveFailures > 0 {
			t.logger.Info("transmission recovered after failures",
				"previous_consecutive_failures", t.consecutiveFailures)
		}
		t.consecutiveFailures = 0
		t.lastFailure = time.Time{}
	}
}

// sendRequest sends a single HTTP request to the backend and measures latency.
// retryCount tracks recursive retries to prevent infinite loops (max 3 retries for 429).
func (t *HTTPTransmitter) sendRequest(ctx context.Context, jsonData []byte, retryCount int) error {
	const maxRateLimitRetries = 3

	// Create request using configured server URL
	req, err := http.NewRequestWithContext(ctx, "POST", t.config.ServerURL+apiDataPath, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.config.APIKey)
	req.Header.Set("User-Agent", fmt.Sprintf("Netwarden-Agent/%s", t.version))

	// Measure request latency
	startTime := time.Now()
	resp, err := t.httpClient.Do(req)
	latency := time.Since(startTime)

	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle rate limiting (429 Too Many Requests)
	if resp.StatusCode == 429 {
		retryAfter := resp.Header.Get("Retry-After")
		interval := resp.Header.Get("X-RateLimit-Interval")
		host := resp.Header.Get("X-RateLimit-Host")

		t.logger.Warn("Rate limited by backend",
			"retry_after", retryAfter,
			"plan_interval", interval,
			"host", host,
			"retry_count", retryCount)

		// Check if we've exceeded max retries
		if retryCount >= maxRateLimitRetries {
			return fmt.Errorf("rate limited: exceeded max retries (%d)", maxRateLimitRetries)
		}

		// Parse retry-after header and wait if provided
		if retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
				waitDuration := time.Duration(seconds) * time.Second
				t.logger.Info("Waiting before retry due to rate limit",
					"wait_seconds", seconds,
					"retry_count", retryCount+1)

				// Wait with context awareness
				select {
				case <-time.After(waitDuration):
					// Retry after waiting with incremented counter
					return t.sendRequest(ctx, jsonData, retryCount+1)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		return fmt.Errorf("rate limited: status 429, retry after %s seconds", retryAfter)
	}

	// Check other response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Provide specific error message for authentication failures
		if resp.StatusCode == 401 {
			return fmt.Errorf("authentication denied: wrong tenant_id or api_key")
		}
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	// Store latency for inclusion in agent_up metric
	t.lastLatencyMs = latency.Milliseconds()

	return nil
}

// createPayload creates the JSON payload structure.
func (t *HTTPTransmitter) createPayload(metrics []metrics.Metric) map[string]interface{} {
	// Convert metrics to simple format
	metricsData := make([]map[string]interface{}, len(metrics))
	var osInfo map[string]interface{}

	for i, metric := range metrics {
		// Use consistent hostname from transmitter
		metricsData[i] = map[string]interface{}{
			"host_id":     t.hostname,
			"metric_name": metric.Name,
			"value":       metric.Value,
			"timestamp":   metric.Timestamp.Format(time.RFC3339),
			"labels":      metric.Labels,
		}

		// Extract detailed OS info from system_info metric
		if metric.Name == "system_info" && metric.Labels != nil {
			osInfo = map[string]interface{}{
				"os":             metric.Labels["os"],
				"platform":       metric.Labels["platform"], // Keep for compatibility
				"family":         metric.Labels["family"],
				"version":        metric.Labels["version"],
				"arch":           metric.Labels["arch"],
				"kernel_version": metric.Labels["kernel_version"],
			}
			// Add distro if present (Linux systems)
			if distro, exists := metric.Labels["distro"]; exists {
				osInfo["distro"] = distro
			}
			if distroVersion, exists := metric.Labels["distro_version"]; exists {
				osInfo["distro_version"] = distroVersion
			}
		}
	}

	// Use consistent hostname from transmitter
	payload := map[string]interface{}{
		"version":   t.version,
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"hostname":  t.hostname,
		"tenant_id": t.config.TenantID, // Include tenant_id from config for validation
		"metrics":   metricsData,
	}

	// Include detailed OS info if available
	if osInfo != nil {
		payload["os_info"] = osInfo
	}

	// Include latency information (including 0ms for sub-millisecond responses)
	if t.lastLatencyMs >= 0 {
		payload["agent_latency"] = t.lastLatencyMs
	}

	return payload
}

// Close closes the transmitter.
func (t *HTTPTransmitter) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.httpClient != nil {
		// Close idle connections
		if transport, ok := t.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	return nil
}
