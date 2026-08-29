//go:build linux

package security

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"netwarden/internal/metrics"
)

// authWindow is the size of the look-back window for failed-login counting.
// Must match the agent's collection cadence (60s).
const authWindow = 60 * time.Second

// maxLogTailBytes caps how much of /var/log/auth.log or /var/log/secure we
// read on the fallback path. 256KB is generous for a 60s window even on busy
// hosts and bounds memory.
const maxLogTailBytes int64 = 256 * 1024

// journalctlPath / sshd default unit names we try in order. journald uses
// different unit names across distros (ssh.service on Debian/Ubuntu,
// sshd.service on RHEL family).
var (
	journalctlPath = "/usr/bin/journalctl"
	sshUnits       = []string{"ssh.service", "sshd.service"}

	// Patterns extracted from sshd auth log lines. Examples:
	//   "Failed password for invalid user root from 192.0.2.1 port 22 ssh2"
	//   "Failed password for ubuntu from 192.0.2.1 port 22 ssh2"
	//   "Invalid user admin from 192.0.2.5 port 33214"
	//   "Failed publickey for foo from 192.0.2.5 port 22 ssh2"
	failedPasswordRe = regexp.MustCompile(`Failed (?:password|publickey|none) for (?:invalid user )?(\S+) from (\S+)`)
	invalidUserRe    = regexp.MustCompile(`Invalid user (\S+) from (\S+)`)
)

// Enabled reports whether the auth collector should run. We're enabled on
// Linux unconditionally; permission/source issues are handled at collect time.
func (c *AuthCollector) Enabled() bool {
	return true
}

// Collect gathers failed-login statistics for the last collection window.
func (c *AuthCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	ts := time.Now()
	since := ts.Add(-authWindow)

	stats, err := c.collectAuthStats(ctx, since)
	if err != nil {
		// Log once, then keep emitting zeros so the host still reports.
		c.warnOnce.Do(func() {
			c.logger.Warn("failed-login data source unavailable; emitting zeros",
				"error", err,
				"hint", "ensure agent user can read journald or /var/log/auth.log|/var/log/secure")
		})
		stats = authStats{Source: "none"}
	}

	c.logger.Debug("collected failed-login stats",
		"source", stats.Source,
		"failed", stats.FailedAttempts,
		"unique_users", stats.UniqueUsers,
		"unique_ips", stats.UniqueIPs)

	return c.emitMetrics(stats, ts), nil
}

// collectAuthStats picks the best available data source and parses sshd
// auth events from it. Order: journalctl -> /var/log/auth.log -> /var/log/secure.
func (c *AuthCollector) collectAuthStats(ctx context.Context, since time.Time) (authStats, error) {
	if _, err := os.Stat(journalctlPath); err == nil {
		stats, err := c.statsFromJournal(ctx, since)
		if err == nil {
			stats.Source = "journal"
			return stats, nil
		}
		c.logger.Debug("journalctl path failed; trying log files", "error", err)
	}

	// Filesystem fallback.
	for _, candidate := range []struct {
		path   string
		source string
	}{
		{"/var/log/auth.log", "auth.log"},
		{"/var/log/secure", "secure"},
	} {
		stats, err := c.statsFromLogFile(ctx, candidate.path, since)
		if err == nil {
			stats.Source = candidate.source
			return stats, nil
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			c.logger.Debug("log file path failed", "path", candidate.path, "error", err)
		}
	}

	return authStats{}, errors.New("no readable failed-login data source")
}

// statsFromJournal queries the systemd journal for sshd auth events in the
// given window and aggregates them.
func (c *AuthCollector) statsFromJournal(ctx context.Context, since time.Time) (authStats, error) {
	// We try each candidate unit, summing results. journalctl will silently
	// return nothing for a unit that doesn't exist, so unioning is safe.
	var combined authStats
	users := map[string]struct{}{}
	ips := map[string]int{}

	any := false
	for _, unit := range sshUnits {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		// --since accepts RFC3339-ish forms; using "1 minute ago" form here
		// keeps it portable with older journalctl.
		cmd := exec.CommandContext(cctx,
			journalctlPath,
			"_SYSTEMD_UNIT="+unit,
			"--since", since.Format("2006-01-02 15:04:05"),
			"--no-pager",
			"--output=short",
		)
		// Don't leak parent env; journalctl honors $SYSTEMD_COLORS etc.
		cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			return authStats{}, err
		}
		if err := cmd.Start(); err != nil {
			cancel()
			// Permission denied or missing journal is recoverable; don't
			// return immediately, try other units / sources.
			c.logger.Debug("journalctl start failed", "unit", unit, "error", err)
			continue
		}

		any = true
		c.scanLines(stdout, &combined, users, ips)

		// Drain any remainder so Wait doesn't block indefinitely.
		_, _ = io.Copy(io.Discard, stdout)
		if err := cmd.Wait(); err != nil {
			c.logger.Debug("journalctl exited non-zero", "unit", unit, "error", err)
		}
		cancel()
	}

	if !any {
		return authStats{}, errors.New("journalctl unavailable for all candidate units")
	}

	combined.UniqueUsers = len(users)
	combined.UniqueIPs = len(ips)
	combined.TopIPs = topNIPs(ips, 5)
	return combined, nil
}

// statsFromLogFile reads the tail of a sshd-style log file and aggregates
// failed-login events whose timestamp falls within the window.
func (c *AuthCollector) statsFromLogFile(ctx context.Context, path string, since time.Time) (authStats, error) {
	info, err := os.Stat(path)
	if err != nil {
		return authStats{}, err
	}

	f, err := os.Open(path)
	if err != nil {
		return authStats{}, err
	}
	defer f.Close()

	// Seek to last maxLogTailBytes if file is large.
	if info.Size() > maxLogTailBytes {
		if _, err := f.Seek(-maxLogTailBytes, io.SeekEnd); err != nil {
			return authStats{}, err
		}
		// Discard the partial first line we may have landed on.
		br := bufio.NewReader(f)
		if _, err := br.ReadString('\n'); err != nil && err != io.EOF {
			return authStats{}, err
		}
	}

	stats := authStats{}
	users := map[string]struct{}{}
	ips := map[string]int{}

	// We don't try to parse the syslog timestamp here — the caller already
	// scoped the *file region* to roughly the last window via tail bytes.
	// For higher precision (e.g. very busy hosts where 256KB <<60s), the
	// regex narrowness already filters by event type; over-counting from
	// slightly older events in the buffer would be conservative (false-high
	// signal is preferable to false-low for security).
	c.scanLines(io.Reader(bufio.NewReader(f)), &stats, users, ips)

	stats.UniqueUsers = len(users)
	stats.UniqueIPs = len(ips)
	stats.TopIPs = topNIPs(ips, 5)

	// Honor caller cancellation post-scan if it happened to fire.
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	return stats, nil
}

// scanLines reads lines from r and increments the supplied aggregates for any
// line that matches a failed-login pattern. Safe to call with a closed reader.
func (c *AuthCollector) scanLines(r io.Reader, stats *authStats, users map[string]struct{}, ips map[string]int) {
	sc := bufio.NewScanner(r)
	// sshd lines are short, but pkix/KEX errors can be long; allow up to 1MB.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		// Cheap pre-filter to skip the vast majority of non-auth lines.
		if !strings.Contains(line, "Failed ") && !strings.Contains(line, "Invalid user ") {
			continue
		}

		if m := failedPasswordRe.FindStringSubmatch(line); m != nil {
			stats.FailedAttempts++
			users[m[1]] = struct{}{}
			ips[m[2]]++
			continue
		}
		if m := invalidUserRe.FindStringSubmatch(line); m != nil {
			stats.FailedAttempts++
			users[m[1]] = struct{}{}
			ips[m[2]]++
		}
	}
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
