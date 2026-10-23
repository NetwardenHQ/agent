// Package security provides security-posture collectors: failed login monitoring
// and SSH server configuration auditing. Both collectors emit metrics under the
// security_* namespace.
package security

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/spool"
)

// AuthCollector tracks failed SSH/login attempts. The implementation is
// platform-specific; on non-Linux platforms it is a no-op stub that simply
// reports as disabled.
type AuthCollector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder

	// One-time warning so we don't spam logs when log sources are unreadable.
	warnOnce sync.Once

	// windowEnd is where the last successful collection stopped reading.
	// The next window starts there, so every event is counted exactly once
	// whatever the collection interval. Zero until the first success.
	mu        sync.Mutex
	windowEnd time.Time

	// spoolDir receives the security events (authevents.go); empty means
	// the spool is off and so are the events, which the agent reports.
	spoolDir string
	failures *failureLog
}

// NewAuthCollector creates a new failed-login collector.
func NewAuthCollector(hostname string, opts ...AuthOption) *AuthCollector {
	c := &AuthCollector{
		hostname: hostname,
		logger:   slog.Default(),
		builder:  metrics.NewBuilder().WithHostname(hostname),
		failures: newFailureLog(10000),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// AuthOption configures the auth collector.
type AuthOption func(*AuthCollector)

// WithSpoolDir sets the spool directory security events are written to.
func WithSpoolDir(dir string) AuthOption {
	return func(c *AuthCollector) { c.spoolDir = dir }
}

// WithAuthLogger sets the logger for the auth collector.
func WithAuthLogger(logger *slog.Logger) AuthOption {
	return func(c *AuthCollector) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// Name returns the collector name.
func (c *AuthCollector) Name() string {
	return "security_auth"
}

// Close performs cleanup (auth collector currently has no resources).
func (c *AuthCollector) Close() error {
	c.logger.Debug("auth collector closed")
	return nil
}

// authStats is the shared shape used by platform-specific implementations
// to return aggregated failed-login data for the most recent window.
type authStats struct {
	// FailedAttempts is the total number of failed login attempts in the window.
	FailedAttempts int

	// UniqueUsers is the number of distinct usernames that appeared in failures.
	UniqueUsers int

	// UniqueIPs is the number of distinct source IPs that appeared in failures.
	UniqueIPs int

	// TopIPs is a small (<=5) list of the most prolific source IPs and their
	// counts, ordered by count descending. Used as a structured snapshot.
	TopIPs []ipCount

	// Source identifies the data source used (journal, auth.log, secure, none).
	Source string

	// Events are the logins and account changes in the window, in log order.
	Events []authEvent
}

// ipCount pairs an IP with the number of failures seen from it.
type ipCount struct {
	IP    string
	Count int
}

// addGauge is a helper for emitting gauge metrics with consistent error handling.
func (c *AuthCollector) addGauge(out *[]metrics.Metric, name string, value float64, ts time.Time) {
	m, err := c.builder.WithTimestamp(ts).Gauge(name, value)
	if err != nil {
		c.logger.Warn("failed to create gauge metric", "name", name, "error", err)
		return
	}
	*out = append(*out, m)
}

// addGaugeWithLabels is a helper for emitting gauge metrics that carry labels.
func (c *AuthCollector) addGaugeWithLabels(out *[]metrics.Metric, name string, value float64, labels map[string]string, ts time.Time) {
	m, err := c.builder.WithTimestamp(ts).GaugeWithLabels(name, value, labels)
	if err != nil {
		c.logger.Warn("failed to create gauge metric with labels", "name", name, "error", err)
		return
	}
	*out = append(*out, m)
}

// emitMetrics produces the security_failed_logins_* gauge family from a stats
// struct, plus security_auth_log_readable = 1. It is only called when a log
// source was read: an unreadable host reports security_auth_log_readable = 0
// and no counts, because a zero would claim nobody tried to log in.
func (c *AuthCollector) emitMetrics(stats authStats, ts time.Time) []metrics.Metric {
	out := make([]metrics.Metric, 0, 5)

	c.addGauge(&out, "security_auth_log_readable", 1, ts)

	c.addGauge(&out, "security_failed_logins", float64(stats.FailedAttempts), ts)
	c.addGauge(&out, "security_failed_logins_unique_users", float64(stats.UniqueUsers), ts)
	c.addGauge(&out, "security_failed_logins_unique_ips", float64(stats.UniqueIPs), ts)

	// Snapshot: top-5 source IPs as a single labeled gauge. We stay within
	// label-cardinality sanity by capping at 5 IPs and only emitting one snapshot
	// metric per cycle.
	if len(stats.TopIPs) > 0 {
		labels := map[string]string{
			"source": stats.Source,
		}
		// Encode top IPs as ip_1=..., count_1=..., ip_2=..., etc.
		for i, ic := range stats.TopIPs {
			if i >= 5 {
				break
			}
			labels[ipLabel(i)] = ic.IP
			labels[countLabel(i)] = formatInt(ic.Count)
		}
		c.addGaugeWithLabels(&out, "security_failed_logins_top_ips", float64(len(stats.TopIPs)), labels, ts)
	}

	return out
}

// ipLabel returns the label key used for the i-th top-IP entry.
func ipLabel(i int) string {
	return "ip_" + indexSuffix(i)
}

// countLabel returns the label key used for the i-th top-IP count.
func countLabel(i int) string {
	return "count_" + indexSuffix(i)
}

// indexSuffix returns the small ASCII index used in label keys (1..5).
func indexSuffix(i int) string {
	switch i {
	case 0:
		return "1"
	case 1:
		return "2"
	case 2:
		return "3"
	case 3:
		return "4"
	case 4:
		return "5"
	default:
		return "n"
	}
}

// formatInt formats a small non-negative int without pulling in strconv at
// every call site. Negative inputs are clamped to 0.
func formatInt(n int) string {
	if n < 0 {
		n = 0
	}
	if n == 0 {
		return "0"
	}
	// Build digits in reverse, then flip.
	buf := make([]byte, 0, 12)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

// Verify interface compliance at compile time.
var _ metrics.Collector = (*AuthCollector)(nil)

// emitEvents writes the window's security events to the spool and reports
// whether events can be recorded at all (security_events_enabled) and how
// many were not written (security_events_dropped). It returns false only when
// the spool write failed, so a caller that can re-read its source (the
// Windows bookmark) does not move past events that were never written.
func (c *AuthCollector) emitEvents(out *[]metrics.Metric, evs []authEvent, ts time.Time) bool {
	if c.spoolDir == "" {
		c.addGauge(out, "security_events_enabled", 0, ts)
		return true
	}
	c.addGauge(out, "security_events_enabled", 1, ts)
	grouped, dropped := groupAuthEvents(evs, func(e authEvent) int { return c.failures.before(e.SourceIP, e.At) }, maxEventGroups)
	// Pruned only now: a login early in the window looks back an hour from
	// its own time, past the hour that ends at ts.
	c.failures.prune(ts)
	written := true
	if err := spool.WriteEvents(c.spoolDir, fmt.Sprintf("agent-auth-%d", ts.UnixNano()), grouped); err != nil {
		c.logger.Warn("security events could not be written to the spool", "dir", c.spoolDir, "error", err)
		dropped += len(grouped)
		written = false
	}
	c.addGauge(out, "security_events_dropped", float64(dropped), ts)
	return written
}

// Each collection counts the events since the previous one ended, so the
// count is right at any collection interval (plans range from one to ten
// minutes). The first collection looks back firstWindow; after a long pause
// a single look-back stops at maxLookBack, so a host that was asleep for a
// day does not read a day of logs in one go.
const (
	firstWindow = 60 * time.Second
	maxLookBack = time.Hour
)

// windowStart is where the window ending at now begins: the end of the last
// successful window, bounded to maxLookBack.
func (c *AuthCollector) windowStart(now time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.windowEnd.IsZero() {
		return now.Add(-firstWindow)
	}
	if now.Sub(c.windowEnd) > maxLookBack {
		return now.Add(-maxLookBack)
	}
	return c.windowEnd
}

func (c *AuthCollector) advanceWindow(end time.Time) {
	c.mu.Lock()
	c.windowEnd = end
	c.mu.Unlock()
}

// inWindow reports whether an event at t belongs to the window (since, until].
// The open start is the previous window's closed end, so no event is counted
// twice.
func inWindow(t, since, until time.Time) bool {
	return t.After(since) && !t.After(until)
}

// topNIPs returns the top n entries from the per-IP count map, ordered by
// count desc and IP asc as a tiebreaker for stable output.
func topNIPs(m map[string]int, n int) []ipCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]ipCount, 0, len(m))
	for ip, count := range m {
		out = append(out, ipCount{IP: ip, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
