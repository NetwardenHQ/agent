package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NetwardenHQ/agent/internal/config"
	sharedhttp "github.com/NetwardenHQ/agent/internal/http"
	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/resilience"
	"github.com/NetwardenHQ/agent/internal/selfupdate"
)

// apiDataPath is the metric submission path, appended to the server URL.
const apiDataPath = "/agent/data"

// maxSnapshotsPerPayload is the contract's limit on the snapshots array: the
// server accepts at most 16. Exceeding it fails schema validation for the
// whole request, so the transmitter truncates instead.
const maxSnapshotsPerPayload = 16

// maxRateLimitRetries bounds how many times a 429 is honored before the
// batch is given up on for this cycle.
const maxRateLimitRetries = 3

// maxRetryAfter caps how long one Retry-After is honored. The server sends
// tens of seconds; a reply asking for an hour comes from a misconfigured or
// hostile server, and honoring it would stall the cycle (and shutdown) that
// long.
const maxRetryAfter = 5 * time.Minute

// rateLimitSleep is sleep, replaceable in tests.
var rateLimitSleep = sleep

// errBackingOff is returned when Send skipped the request entirely because
// of recent failures. No request was made, so it is not an attempt.
var errBackingOff = errors.New("backing off after consecutive transmission failures")

// payload is the /agent/data request body. Field names are the server's
// contract; omitempty on the optional ones matters because the server
// distinguishes an absent field from an empty one.
type payload struct {
	Version   string             `json:"version"`
	OS        string             `json:"os"`
	Arch      string             `json:"arch"`
	Hostname  string             `json:"hostname"`
	TenantID  string             `json:"tenant_id"`
	Metrics   []payloadMetric    `json:"metrics"`
	OSInfo    map[string]string  `json:"os_info,omitempty"`
	Latency   *int64             `json:"agent_latency,omitempty"`
	Snapshots []metrics.Snapshot `json:"snapshots,omitempty"`
	// SelfUpdate is "enabled", "disabled" or "unsupported", so the platform
	// knows which hosts keep themselves current.
	SelfUpdate string `json:"self_update,omitempty"`
}

// payloadMetric is one metric as the server expects it.
type payloadMetric struct {
	HostID     string            `json:"host_id"`
	MetricName string            `json:"metric_name"`
	Value      float64           `json:"value"`
	Timestamp  string            `json:"timestamp"`
	Labels     map[string]string `json:"labels"`
}

// toPayloadMetric converts one metric to its wire form. host_id is the
// hostname the agent reports as.
func toPayloadMetric(hostID string, m metrics.Metric) payloadMetric {
	return payloadMetric{
		HostID:     hostID,
		MetricName: m.Name,
		Value:      m.Value,
		Timestamp:  m.Timestamp.Format(time.RFC3339),
		Labels:     m.Labels,
	}
}

// serverResponse is the subset of the /agent/data reply the agent acts on.
//
// The agent reports its version in every payload; when a newer release exists
// the server names it here, along with where to get it, what it must hash to
// and, for packages that carry no signature of their own, the release
// signature. All of it is a suggestion: local configuration outranks it, and
// the agent will not install anything not signed by a key pinned on the host
// itself. See internal/selfupdate for the precedence rules.
type serverResponse struct {
	Data struct {
		AgentUpdate *struct {
			Version     string `json:"version"`
			URL         string `json:"url"`
			SHA256      string `json:"sha256"`
			Signature   string `json:"signature"`
			Certificate string `json:"certificate"`
		} `json:"agent_update,omitempty"`
	} `json:"data"`
}

// maxResponseBytes caps how much of a reply is read. The body is a small JSON
// ack; anything larger comes from a malfunctioning or hostile server and must
// not exhaust the agent's memory.
const maxResponseBytes = 64 * 1024

// HTTPTransmitter sends metrics to the Netwarden backend.
type HTTPTransmitter struct {
	config     *config.Config
	logger     *slog.Logger
	httpClient *http.Client
	version    string
	hostname   string

	// lastLatencyMs is the round-trip time of the last successful request,
	// reported in the next payload. -1 until the first measurement, which
	// omits the field rather than claiming zero.
	lastLatencyMs atomic.Int64

	// lastStatus is the HTTP status of the last reply, 0 when none arrived.
	lastStatus atomic.Int64

	// onUpdateHint, when set, is called with the version the server says is
	// current. The transmitter only reports the hint; deciding whether and
	// when to act on it belongs to the updater, not to the metrics path.
	onUpdateHint func(selfupdate.Offer)

	// selfUpdateState, when set, reports the updater's state in each payload.
	selfUpdateState func() string

	mu                  sync.Mutex
	consecutiveFailures int
	lastFailure         time.Time
}

// NewHTTPTransmitter creates a transmitter for the configured server.
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
		httpClient: sharedhttp.GetClient(),
	}
	t.lastLatencyMs.Store(-1)
	return t, nil
}

// Send transmits one batch, retrying transient failures.
//
// snapshots carries structured security snapshots for this cycle and may be
// nil. The agent attaches them to a single batch per cycle so the server
// upserts each snapshot type once and runs its findings evaluator once,
// rather than once per batch.
func (t *HTTPTransmitter) Send(ctx context.Context, metricList []metrics.Metric, snapshots []metrics.Snapshot) error {
	if len(metricList) == 0 && len(snapshots) == 0 {
		return nil
	}

	if t.shouldBackoff() {
		return fmt.Errorf("%w (%d)", errBackingOff, t.failureCount())
	}

	body, err := json.Marshal(t.createPayload(metricList, snapshots))
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	err = resilience.Retry(ctx, func() error {
		return t.sendWithRateLimit(ctx, body)
	})
	t.recordOutcome(err)

	if err != nil {
		t.logger.Warn("failed to send metrics", "error", err, "count", len(metricList))
		return err
	}
	t.logger.Debug("sent metrics", "count", len(metricList), "snapshots", len(snapshots))
	return nil
}

// shouldBackoff reports whether recent failures mean this cycle should be
// skipped. After three consecutive failures the transmitter waits 30 s,
// then 60 s, 120 s, 240 s, capped at 300 s, before trying again; the
// collectors keep running so the delta filter's state stays current.
func (t *HTTPTransmitter) shouldBackoff() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.consecutiveFailures < 3 {
		return false
	}
	backoff := min(30*time.Second<<uint(t.consecutiveFailures-3), 300*time.Second)
	return time.Since(t.lastFailure) < backoff
}

// failureCount returns the current consecutive-failure count.
func (t *HTTPTransmitter) failureCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.consecutiveFailures
}

// recordOutcome updates the failure counters after a Send.
func (t *HTTPTransmitter) recordOutcome(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err != nil {
		t.consecutiveFailures++
		t.lastFailure = time.Now()
		// Persistent failure often means the pooled connection is dead in a
		// way the transport has not noticed (NAT timeout, server restart).
		// Drop the pool so the next attempt dials fresh.
		if t.consecutiveFailures%5 == 0 {
			if transport, ok := t.httpClient.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
			t.logger.Info("cleared idle connections after persistent failures",
				"consecutive_failures", t.consecutiveFailures)
		}
		return
	}

	if t.consecutiveFailures > 0 {
		t.logger.Info("transmission recovered", "previous_consecutive_failures", t.consecutiveFailures)
	}
	t.consecutiveFailures = 0
	t.lastFailure = time.Time{}
}

// rateLimitedError is a 429 that named how long to wait.
type rateLimitedError struct{ wait time.Duration }

func (e *rateLimitedError) Error() string {
	return fmt.Sprintf("rate limited: retry after %v", e.wait)
}

// sendWithRateLimit performs the POST, honoring a 429's Retry-After (capped at
// maxRetryAfter) at most maxRateLimitRetries times. Running out of retries is
// a permanent error for this Send, so resilience.Retry's attempts do not each
// honor another round of 429s.
func (t *HTTPTransmitter) sendWithRateLimit(ctx context.Context, body []byte) error {
	for retries := 0; ; retries++ {
		err := t.sendRequest(ctx, body)
		var rl *rateLimitedError
		if !errors.As(err, &rl) {
			return err
		}
		if retries >= maxRateLimitRetries {
			return resilience.Permanent(fmt.Errorf("rate limited: exceeded %d retries", maxRateLimitRetries))
		}
		if err := rateLimitSleep(ctx, min(rl.wait, maxRetryAfter)); err != nil {
			return err
		}
	}
}

// sendRequest performs one POST and records its latency.
func (t *HTTPTransmitter) sendRequest(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.config.ServerURL+apiDataPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.config.APIKey)
	req.Header.Set("User-Agent", "Netwarden-Agent/"+t.version)

	start := time.Now()
	resp, err := t.httpClient.Do(req)
	latency := time.Since(start)
	if err != nil {
		t.lastStatus.Store(0)
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	t.lastStatus.Store(int64(resp.StatusCode))

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		retryAfter := resp.Header.Get("Retry-After")
		t.logger.Warn("rate limited by server",
			"retry_after", retryAfter,
			"plan_interval", resp.Header.Get("X-RateLimit-Interval"),
			"host", resp.Header.Get("X-RateLimit-Host"))

		seconds, err := strconv.Atoi(retryAfter)
		if err != nil || seconds <= 0 {
			return fmt.Errorf("rate limited: status 429, Retry-After %q", retryAfter)
		}
		return &rateLimitedError{wait: time.Duration(seconds) * time.Second}

	case resp.StatusCode == http.StatusUnauthorized:
		return resilience.Permanent(fmt.Errorf("authentication denied: wrong tenant_id or api_key"))

	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooEarly:
		// 408 and 425 say "not now", not "not this": the same bytes can
		// succeed on a retry.
		return fmt.Errorf("server returned status %d", resp.StatusCode)

	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// The server rejected this payload; sending the same bytes again
		// cannot succeed.
		return resilience.Permanent(fmt.Errorf("server rejected payload: status %d", resp.StatusCode))

	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	// Read the body even when there is nothing to act on: Go reuses a
	// keep-alive connection only once the previous response has been drained.
	t.handleResponse(resp.Body)

	t.lastLatencyMs.Store(latency.Milliseconds())
	return nil
}

// handleResponse drains the reply and surfaces an update hint if one is
// present. It never fails: the metrics were accepted, and an unparseable
// reply must not turn a successful send into a retry.
func (t *HTTPTransmitter) handleResponse(body io.Reader) {
	raw, err := io.ReadAll(io.LimitReader(body, maxResponseBytes))
	if err != nil || len(raw) == 0 {
		return
	}

	var parsed serverResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.logger.Debug("could not parse server response", "error", err)
		return
	}
	if parsed.Data.AgentUpdate == nil || parsed.Data.AgentUpdate.Version == "" {
		return
	}
	if t.onUpdateHint == nil {
		return
	}
	t.onUpdateHint(selfupdate.Offer{
		Version:     parsed.Data.AgentUpdate.Version,
		URL:         parsed.Data.AgentUpdate.URL,
		SHA256:      parsed.Data.AgentUpdate.SHA256,
		Signature:   parsed.Data.AgentUpdate.Signature,
		Certificate: parsed.Data.AgentUpdate.Certificate,
	})
}

// SetUpdateHintHandler registers the callback invoked when the server reports
// a newer agent version. Call before Send.
func (t *HTTPTransmitter) SetUpdateHintHandler(fn func(selfupdate.Offer)) {
	t.onUpdateHint = fn
}

// SetSelfUpdateState registers the function that reports the updater's state
// in each payload. Call before Send.
func (t *HTTPTransmitter) SetSelfUpdateState(fn func() string) {
	t.selfUpdateState = fn
}

// createPayload builds the request body for one batch.
func (t *HTTPTransmitter) createPayload(metricList []metrics.Metric, snapshots []metrics.Snapshot) payload {
	p := payload{
		Version:  t.version,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: t.hostname,
		TenantID: t.config.TenantID,
		Metrics:  make([]payloadMetric, len(metricList)),
	}

	for i, m := range metricList {
		p.Metrics[i] = toPayloadMetric(t.hostname, m)

		// The system_info metric carries the host's OS details in its
		// labels; the server reads them from the top-level os_info field.
		if m.Name == "system_info" && m.Labels != nil {
			p.OSInfo = map[string]string{
				"os":             m.Labels["os"],
				"platform":       m.Labels["platform"],
				"family":         m.Labels["family"],
				"version":        m.Labels["version"],
				"arch":           m.Labels["arch"],
				"kernel_version": m.Labels["kernel_version"],
			}
			if distro, ok := m.Labels["distro"]; ok {
				p.OSInfo["distro"] = distro
			}
			if distroVersion, ok := m.Labels["distro_version"]; ok {
				p.OSInfo["distro_version"] = distroVersion
			}
		}
	}

	if ms := t.lastLatencyMs.Load(); ms >= 0 {
		p.Latency = &ms
	}
	if t.selfUpdateState != nil {
		p.SelfUpdate = t.selfUpdateState()
	}

	if len(snapshots) > maxSnapshotsPerPayload {
		t.logger.Warn("truncating snapshots to server limit",
			"count", len(snapshots), "limit", maxSnapshotsPerPayload)
		snapshots = snapshots[:maxSnapshotsPerPayload]
	}
	if len(snapshots) > 0 {
		p.Snapshots = snapshots
	}

	return p
}

// Close drops pooled connections.
func (t *HTTPTransmitter) Close() error {
	if transport, ok := t.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// LastStatus returns the HTTP status of the most recent reply, 0 when the
// last attempt got none.
func (t *HTTPTransmitter) LastStatus() int { return int(t.lastStatus.Load()) }
