// Package security provides security-posture collectors: failed login monitoring
// and SSH server configuration auditing. Both collectors emit metrics under the
// security_* namespace.
package security

import (
	"log/slog"
	"sync"
	"time"

	"netwarden/internal/metrics"
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
}

// NewAuthCollector creates a new failed-login collector.
func NewAuthCollector(hostname string, opts ...AuthOption) *AuthCollector {
	c := &AuthCollector{
		hostname: hostname,
		logger:   slog.Default(),
		builder:  metrics.NewBuilder().WithHostname(hostname),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// AuthOption configures the auth collector.
type AuthOption func(*AuthCollector)

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
// struct. Used by both the live path and the "permission denied / no source"
// fallback path so we always report something (even zeros).
func (c *AuthCollector) emitMetrics(stats authStats, ts time.Time) []metrics.Metric {
	out := make([]metrics.Metric, 0, 4)

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
