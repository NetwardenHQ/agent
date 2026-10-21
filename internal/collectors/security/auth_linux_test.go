//go:build linux

package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

func metricValues(ms []metrics.Metric) map[string]float64 {
	out := make(map[string]float64, len(ms))
	for _, m := range ms {
		out[m.Name] = m.Value
	}
	return out
}

// useSources points the collector at test files for the duration of a test.
func useSources(t *testing.T, journal string, files ...string) {
	t.Helper()
	oldJournal, oldFiles := journalctlPath, authLogFiles
	journalctlPath = journal
	authLogFiles = nil
	for _, f := range files {
		authLogFiles = append(authLogFiles, struct{ path, source string }{f, filepath.Base(f)})
	}
	t.Cleanup(func() { journalctlPath, authLogFiles = oldJournal, oldFiles })
}

func TestCollectReportsUnreadableInsteadOfZeros(t *testing.T) {
	dir := t.TempDir()
	useSources(t, filepath.Join(dir, "no-journalctl"), filepath.Join(dir, "missing.log"))

	c := NewAuthCollector("test")
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := metricValues(ms)
	if len(got) != 1 || got["security_auth_log_readable"] != 0 {
		t.Fatalf("want only security_auth_log_readable=0, got %v", got)
	}
	if _, ok := got["security_failed_logins"]; ok {
		t.Fatal("an unreadable host must not report a failed-login count")
	}
	if !c.windowEnd.IsZero() {
		t.Fatal("a failed collection must not advance the window")
	}
}

func TestWindowsChainWithoutGapOrOverlap(t *testing.T) {
	c := NewAuthCollector("test")
	t0 := time.Date(2026, 10, 20, 21, 0, 0, 0, time.UTC)

	if got := c.windowStart(t0); !got.Equal(t0.Add(-firstWindow)) {
		t.Fatalf("first window starts %v, want %v", got, t0.Add(-firstWindow))
	}
	c.advanceWindow(t0)

	// A ten-minute interval: the next window starts exactly where this one ended.
	t1 := t0.Add(10 * time.Minute)
	if got := c.windowStart(t1); !got.Equal(t0) {
		t.Fatalf("second window starts %v, want %v", got, t0)
	}

	// An event exactly on the boundary belongs to the earlier window only.
	if !inWindow(t0, t0.Add(-firstWindow), t0) || inWindow(t0, t0, t1) {
		t.Fatal("boundary event counted in both windows or neither")
	}
}

func TestWindowLookBackIsCapped(t *testing.T) {
	c := NewAuthCollector("test")
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	c.advanceWindow(t0)
	later := t0.Add(26 * time.Hour)
	if got := c.windowStart(later); !got.Equal(later.Add(-maxLookBack)) {
		t.Fatalf("look-back after a long pause starts %v, want %v", got, later.Add(-maxLookBack))
	}
}

func TestLogFileCountsOnlyTheWindow(t *testing.T) {
	now := time.Now()
	ts := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339Nano) }
	trad := func(ago time.Duration) string { return now.Add(-ago).Format("Jan _2 15:04:05") }
	lines := []string{
		ts(30*time.Minute) + " web sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2", // before the window
		ts(5*time.Minute) + " web sshd[2]: Failed password for root from 192.0.2.1 port 22 ssh2",
		ts(4*time.Minute) + " web sshd[3]: Invalid user admin from 192.0.2.7 port 4022",
		trad(3*time.Minute) + " web sshd[4]: Failed publickey for deploy from 198.51.100.4 port 22 ssh2",
		"garbage without a timestamp Failed password for root from 192.0.2.9 port 22 ssh2",
		ts(2*time.Minute) + " web sshd[5]: Accepted publickey for deploy from 198.51.100.4 port 22 ssh2",
	}
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewAuthCollector("test")
	stats, err := c.statsFromLogFile(context.Background(), path, now.Add(-10*time.Minute), now)
	if err != nil {
		t.Fatalf("statsFromLogFile: %v", err)
	}
	if stats.FailedAttempts != 3 || stats.UniqueIPs != 3 || stats.UniqueUsers != 3 {
		t.Fatalf("got %d attempts, %d IPs, %d users; want 3, 3, 3", stats.FailedAttempts, stats.UniqueIPs, stats.UniqueUsers)
	}

	// The same file read for the next window counts nothing again.
	stats, err = c.statsFromLogFile(context.Background(), path, now, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("statsFromLogFile: %v", err)
	}
	if stats.FailedAttempts != 0 {
		t.Fatalf("next window recounted %d attempts", stats.FailedAttempts)
	}
}

func TestCollectReadsALogFileAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	line := time.Now().Add(-10*time.Second).Format(time.RFC3339Nano) +
		" web sshd[9]: Failed password for root from 192.0.2.1 port 22 ssh2\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	useSources(t, filepath.Join(dir, "no-journalctl"), path)

	ms, err := NewAuthCollector("test").Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := metricValues(ms)
	if got["security_auth_log_readable"] != 1 || got["security_failed_logins"] != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestJournalTime(t *testing.T) {
	got, ok := journalTime("1792534700.123456 web sshd[812]: Failed password for root from 192.0.2.1 port 22 ssh2")
	if !ok || got.Unix() != 1792534700 || got.Nanosecond() != 123456000 {
		t.Fatalf("got %v %v", got, ok)
	}
	if _, ok := journalTime("-- No entries --"); ok {
		t.Fatal("parsed a journal banner as a timestamp")
	}
}

func TestSyslogTimeYearRollover(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 5, 0, 0, time.UTC)
	got, ok := syslogTime("Dec 31 23:59:30 web sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2", now)
	if !ok || got.Year() != 2026 {
		t.Fatalf("December line read in January got %v %v, want year 2026", got, ok)
	}
}
