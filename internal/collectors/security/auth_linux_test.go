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

func writeAuthLog(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Debian 13 and Ubuntu 26.04 log each session from sshd-session, not sshd.
func TestParseIgnoresProgramName(t *testing.T) {
	now := time.Now()
	ts := now.Add(-time.Minute).Format(time.RFC3339Nano)
	path := writeAuthLog(t, []string{
		ts + " web sshd-session[912]: Accepted publickey for deploy from 198.51.100.4 port 51122 ssh2: ED25519 SHA256:abc",
		ts + " web sshd[913]: Accepted publickey for deploy from 198.51.100.4 port 51123 ssh2: ED25519 SHA256:abc",
	})
	stats, err := NewAuthCollector("test").statsFromLogFile(context.Background(), path, now.Add(-10*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(stats.Events))
	}
	a, b := stats.Events[0], stats.Events[1]
	if a.Type != "ssh.login" || a.Type != b.Type || a.User != b.User || a.SourceIP != b.SourceIP || a.KeyFP != b.KeyFP {
		t.Fatalf("sshd-session and sshd lines differ: %+v / %+v", a, b)
	}
	if a.Key == b.Key || !strings.HasPrefix(a.Key, "auth:") || len(a.Key) != len("auth:")+32 {
		t.Fatalf("dedupe keys: %q %q", a.Key, b.Key)
	}
}

func TestNoFailedUsernamesInEvents(t *testing.T) {
	now := time.Now()
	ts := now.Add(-time.Minute).Format(time.RFC3339Nano)
	path := writeAuthLog(t, []string{ts + " web sshd[1]: Failed password for hunter2 from 203.0.113.9 port 22 ssh2"})
	stats, err := NewAuthCollector("test").statsFromLogFile(context.Background(), path, now.Add(-10*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.FailedAttempts != 1 || len(stats.Events) != 0 {
		t.Fatalf("got %d failures and events %+v", stats.FailedAttempts, stats.Events)
	}
}

func TestCollectWritesEventsToTheSpool(t *testing.T) {
	now := time.Now()
	ts := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339Nano) }
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, ts(50*time.Second-time.Duration(i)*time.Second)+" web sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2")
	}
	lines = append(lines,
		ts(30*time.Second)+" web sshd-session[2]: Accepted password for root from 203.0.113.9 port 22 ssh2",
		ts(20*time.Second)+" web useradd[3]: new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash, from=/dev/pts/0",
		ts(10*time.Second)+" web usermod[4]: add 'bob' to group 'sudo'",
	)
	path := writeAuthLog(t, lines)
	dir := t.TempDir()
	useSources(t, filepath.Join(dir, "no-journalctl"), path)
	spoolDir := filepath.Join(dir, "spool")

	ms, err := NewAuthCollector("test", WithSpoolDir(spoolDir)).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := metricValues(ms); got["security_events_enabled"] != 1 || got["security_failed_logins"] != 5 {
		t.Fatalf("metrics %v", got)
	}
	files, _ := filepath.Glob(filepath.Join(spoolDir, "events", "agent-auth-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("spool files %v", files)
	}
	body, _ := os.ReadFile(files[0])
	text := string(body)
	for _, want := range []string{`"type":"ssh.login"`, `"prior_failures":"5"`, `"type":"account.created"`, `"type":"account.admin_granted"`, `"group":"sudo"`} {
		if !strings.Contains(text, want) {
			t.Errorf("spool file lacks %s:\n%s", want, text)
		}
	}
}

func TestCollectWithoutASpoolSaysSo(t *testing.T) {
	dir := t.TempDir()
	path := writeAuthLog(t, []string{time.Now().Add(-10*time.Second).Format(time.RFC3339Nano) +
		" web sshd[2]: Accepted password for root from 203.0.113.9 port 22 ssh2"})
	useSources(t, filepath.Join(dir, "no-journalctl"), path)
	ms, err := NewAuthCollector("test").Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := metricValues(ms); got["security_events_enabled"] != 0 {
		t.Fatalf("metrics %v", got)
	}
}
