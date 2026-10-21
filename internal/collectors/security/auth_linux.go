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
	"strconv"
	"strings"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Each collection counts the events since the previous one ended, so the
// count is right at any collection interval (plans range from one to ten
// minutes). The first collection looks back firstWindow; after a long pause
// a single look-back stops at maxLookBack, so a host that was asleep for a
// day does not read a day of logs in one go.
const (
	firstWindow = 60 * time.Second
	maxLookBack = time.Hour
)

// maxLogTailBytes caps how much of /var/log/auth.log or /var/log/secure we
// scan on the fallback path. A busy sshd under a brute-force run writes a
// few hundred bytes per attempt; 4 MiB holds over ten thousand attempts,
// which covers a ten-minute window with room to spare. Lines are streamed,
// so this bounds reading time, not memory.
const maxLogTailBytes int64 = 4 << 20

// journalctlPath / sshd default unit names we try in order. journald uses
// different unit names across distros (ssh.service on Debian/Ubuntu,
// sshd.service on RHEL family).
var (
	journalctlPath = "/usr/bin/journalctl"
	sshUnits       = []string{"ssh.service", "sshd.service"}

	// Syslog files tried in order when the journal is not available.
	authLogFiles = []struct{ path, source string }{
		{"/var/log/auth.log", "auth.log"},
		{"/var/log/secure", "secure"},
	}

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

// Collect gathers failed-login statistics for the events since the previous
// collection.
func (c *AuthCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	ts := time.Now()
	since := c.windowStart(ts)

	stats, err := c.collectAuthStats(ctx, since, ts)
	if err != nil {
		c.warnOnce.Do(func() {
			c.logger.Warn("failed-login data source unavailable; reporting it as unreadable",
				"error", err,
				"hint", "ensure agent user can read journald or /var/log/auth.log|/var/log/secure")
		})
		// The window is not advanced: once a source becomes readable, the
		// next collection picks up from where the last good one stopped.
		var out []metrics.Metric
		c.addGauge(&out, "security_auth_log_readable", 0, ts)
		return out, nil
	}
	c.advanceWindow(ts)

	c.logger.Debug("collected failed-login stats",
		"source", stats.Source,
		"since", since,
		"failed", stats.FailedAttempts,
		"unique_users", stats.UniqueUsers,
		"unique_ips", stats.UniqueIPs)

	return c.emitMetrics(stats, ts), nil
}

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

// collectAuthStats picks the best available data source and parses sshd
// auth events from it. Order: journalctl -> /var/log/auth.log -> /var/log/secure.
func (c *AuthCollector) collectAuthStats(ctx context.Context, since, until time.Time) (authStats, error) {
	if _, err := os.Stat(journalctlPath); err == nil {
		stats, err := c.statsFromJournal(ctx, since, until)
		if err == nil {
			stats.Source = "journal"
			return stats, nil
		}
		c.logger.Debug("journalctl path failed; trying log files", "error", err)
	}

	// Filesystem fallback.
	for _, candidate := range authLogFiles {
		stats, err := c.statsFromLogFile(ctx, candidate.path, since, until)
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
func (c *AuthCollector) statsFromJournal(ctx context.Context, since, until time.Time) (authStats, error) {
	// We try each candidate unit, summing results. journalctl will silently
	// return nothing for a unit that doesn't exist, so unioning is safe.
	var combined authStats
	users := map[string]struct{}{}
	ips := map[string]int{}

	any := false
	for _, unit := range sshUnits {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		// --since/--until take whole seconds in local time, so the query is
		// widened by a second on each side and short-unix output gives every
		// line its exact timestamp to filter on.
		cmd := exec.CommandContext(cctx,
			journalctlPath,
			"_SYSTEMD_UNIT="+unit,
			"--since", since.Add(-time.Second).Format("2006-01-02 15:04:05"),
			"--until", until.Add(time.Second).Format("2006-01-02 15:04:05"),
			"--no-pager",
			"--output=short-unix",
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
		c.scanLines(stdout, journalTime, since, until, &combined, users, ips)

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
func (c *AuthCollector) statsFromLogFile(ctx context.Context, path string, since, until time.Time) (authStats, error) {
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

	// The tail holds far more than one window, so every line is placed by
	// its own timestamp. Without that, each collection would count the same
	// attempts again for as long as they stayed in the tail.
	now := time.Now()
	c.scanLines(bufio.NewReader(f), func(line string) (time.Time, bool) { return syslogTime(line, now) }, since, until, &stats, users, ips)

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
// line in the window that matches a failed-login pattern. A line whose time
// cannot be read is skipped rather than guessed into the window. Safe to call
// with a closed reader.
func (c *AuthCollector) scanLines(r io.Reader, timeOf func(string) (time.Time, bool), since, until time.Time,
	stats *authStats, users map[string]struct{}, ips map[string]int) {
	sc := bufio.NewScanner(r)
	// sshd lines are short, but pkix/KEX errors can be long; allow up to 1MB.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		// Cheap pre-filter to skip the vast majority of non-auth lines.
		if !strings.Contains(line, "Failed ") && !strings.Contains(line, "Invalid user ") {
			continue
		}
		if t, ok := timeOf(line); !ok || !inWindow(t, since, until) {
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

// journalTime reads the timestamp journalctl --output=short-unix puts first
// on each line: seconds since the epoch with a fractional part.
func journalTime(line string) (time.Time, bool) {
	field, _, ok := strings.Cut(line, " ")
	if !ok {
		return time.Time{}, false
	}
	secs, frac, _ := strings.Cut(field, ".")
	sec, err := strconv.ParseInt(secs, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	var nsec int64
	if frac != "" {
		if len(frac) > 9 {
			frac = frac[:9]
		}
		n, err := strconv.ParseInt(frac, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		for i := len(frac); i < 9; i++ {
			n *= 10
		}
		nsec = n
	}
	return time.Unix(sec, nsec), true
}

// syslogTime reads the timestamp at the start of a syslog line in either of
// the formats rsyslog writes:
//
//	2026-10-20T21:13:01.123456+00:00 host sshd[812]: ...   (RFC 3339, newer distributions)
//	Oct 20 21:13:01 host sshd[812]: ...                    (traditional, local time, no year)
//
// The traditional form has no year; it is taken as the current one, or the
// previous one when that would put the line in the future (a January read of
// December lines).
func syslogTime(line string, now time.Time) (time.Time, bool) {
	if field, _, ok := strings.Cut(line, " "); ok && len(field) >= 19 && field[4] == '-' && field[10] == 'T' {
		t, err := time.Parse(time.RFC3339Nano, field)
		return t, err == nil
	}
	if len(line) < 15 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], now.Location())
	if err != nil {
		return time.Time{}, false
	}
	t = t.AddDate(now.Year(), 0, 0)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
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
