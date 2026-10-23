//go:build windows

package security

import (
	"context"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// On Windows the failed-login counts and the security events come from the
// Security event log (winlog_windows.go, winlog_parse.go) instead of journald
// or auth.log; the metrics are the same family the Linux collector reports.

// Enabled is true: every supported Windows has a Security log.
func (c *AuthCollector) Enabled() bool {
	return true
}

// Collect reads the Security log since the last collection.
func (c *AuthCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	ts := time.Now()
	since := c.windowStart(ts)
	records, commit, err := readSecurityLog(ts.Sub(since))
	if err != nil {
		c.warnOnce.Do(func() {
			c.logger.Warn("Security event log unreadable; reporting it as unreadable",
				"error", err, "hint", "the agent service must run as LocalSystem")
		})
		var out []metrics.Metric
		c.addGauge(&out, "security_auth_log_readable", 0, ts)
		return out, nil
	}

	stats := authStats{Source: "eventlog"}
	users := map[string]struct{}{}
	ips := map[string]int{}
	for _, r := range records {
		o, ok := classifyWinRecord(r, lookupSID)
		if !ok {
			continue
		}
		if o.Failure {
			stats.FailedAttempts++
			if o.FailedUser != "" {
				users[o.FailedUser] = struct{}{}
			}
			if o.FailedIP != "" {
				ips[o.FailedIP]++
				c.failures.add(o.FailedIP, r.Time)
			}
			continue
		}
		stats.Events = append(stats.Events, *o.Event)
	}
	stats.UniqueUsers = len(users)
	stats.UniqueIPs = len(ips)
	stats.TopIPs = topNIPs(ips, 5)

	out := c.emitMetrics(stats, ts)
	if c.emitEvents(&out, stats.Events, ts) {
		commit()
		c.advanceWindow(ts)
	}
	if logon, accounts, ok := auditCoverage(); ok {
		c.addGauge(&out, "security_audit_logon", boolGauge(logon), ts)
		c.addGauge(&out, "security_audit_account_management", boolGauge(accounts), ts)
	}
	return out, nil
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
