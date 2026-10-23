package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

func TestParseAccepted(t *testing.T) {
	ev, ok := parseAuthMessage("Accepted publickey for deploy from 198.51.100.4 port 51122 ssh2: ED25519 SHA256:abc")
	if !ok || ev.Type != "ssh.login" || ev.User != "deploy" || ev.SourceIP != "198.51.100.4" ||
		ev.Method != "publickey" || ev.KeyFP != "SHA256:abc" {
		t.Fatalf("publickey login: %+v %v", ev, ok)
	}
	ev, ok = parseAuthMessage("Accepted password for alice from 2001:db8::5 port 22 ssh2")
	if !ok || ev.User != "alice" || ev.SourceIP != "2001:db8::5" || ev.Method != "password" || ev.KeyFP != "" {
		t.Fatalf("password login: %+v %v", ev, ok)
	}
	ev, ok = parseAuthMessage("Accepted publickey for ops from 192.0.2.4 port 2222 ssh2: ED25519-CERT SHA256:xyz ID ops@corp (serial 7) CA ED25519 SHA256:ca")
	if !ok || ev.User != "ops" || ev.KeyFP != "SHA256:xyz" {
		t.Fatalf("certificate login: %+v %v", ev, ok)
	}
	ev, ok = parseAuthMessage("Accepted keyboard-interactive/pam for bob from 192.0.2.8 port 40000 ssh2")
	if !ok || ev.Method != "keyboard-interactive/pam" {
		t.Fatalf("pam login: %+v %v", ev, ok)
	}
}

func TestParseAccountTools(t *testing.T) {
	cases := []struct {
		msg                  string
		typ, user, group, by string
		ok                   bool
	}{
		{"new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash, from=/dev/pts/0", "account.created", "bob", "", "", true},
		{"add 'bob' to group 'sudo'", "account.admin_granted", "bob", "sudo", "", true},
		{"add 'bob' to group 'docker'", "", "", "", "", false},
		{"add 'bob' to shadow group 'sudo'", "", "", "", "", false},
		{"user bob added by root to group wheel", "account.admin_granted", "bob", "wheel", "root", true},
		{"user bob added by root to group users", "", "", "", "", false},
		{"Failed password for hunter2 from 203.0.113.9 port 22 ssh2", "", "", "", "", false},
		{"session opened for user root(uid=0) by alice(uid=1000)", "", "", "", "", false},
	}
	for _, c := range cases {
		ev, ok := parseAuthMessage(c.msg)
		if ok != c.ok || ev.Type != c.typ || ev.User != c.user || ev.Group != c.group || ev.By != c.by {
			t.Errorf("%q: got %+v %v", c.msg, ev, ok)
		}
	}
}

func TestPriorFailures(t *testing.T) {
	at := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := newFailureLog(10000)
	for _, ago := range []time.Duration{50, 40, 30, 20, 10, 70} {
		f.add("203.0.113.9", at.Add(-ago*time.Minute))
	}
	f.add("203.0.113.9", at.Add(time.Minute)) // after the login: not before it
	f.add("198.51.100.1", at.Add(-5*time.Minute))
	if n := f.before("203.0.113.9", at); n != 5 {
		t.Fatalf("before = %d, want 5", n)
	}
	evs, dropped := groupAuthEvents([]authEvent{{Type: "ssh.login", User: "alice", SourceIP: "203.0.113.9", Method: "password", At: at, Key: "auth:1"}},
		func(e authEvent) int { return f.before(e.SourceIP, e.At) }, 100)
	if dropped != 0 || len(evs) != 1 || evs[0].Labels["prior_failures"] != "5" {
		t.Fatalf("got %+v dropped %d", evs, dropped)
	}
}

func TestFailureLogIsBounded(t *testing.T) {
	at := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := newFailureLog(3)
	for i := 0; i < 10; i++ {
		f.add(fmt.Sprintf("192.0.2.%d", i), at.Add(time.Duration(i)*time.Second))
	}
	if len(f.byIP) > 3 {
		t.Fatalf("holds %d IPs, cap 3", len(f.byIP))
	}
	if f.before("192.0.2.9", at.Add(time.Minute)) != 1 {
		t.Fatal("the newest IP was evicted")
	}
}

func TestGroupingAndCap(t *testing.T) {
	at := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var evs []authEvent
	for i := 0; i < 40; i++ {
		evs = append(evs, authEvent{Type: "ssh.login", User: "ansible", SourceIP: "10.0.0.2", Method: "publickey",
			At: at.Add(time.Duration(i) * time.Second), Key: fmt.Sprintf("auth:%d", i)})
	}
	out, dropped := groupAuthEvents(evs, func(authEvent) int { return 0 }, 100)
	if dropped != 0 || len(out) != 1 {
		t.Fatalf("40 identical logins: %d events, %d dropped", len(out), dropped)
	}
	e := out[0]
	if e.Labels["count"] != "40" || e.OccurredAt != at.Format(time.RFC3339) || e.DedupeKey != "auth:0" ||
		e.Title != "ansible logged in over SSH from 10.0.0.2 (40 times)" || e.Severity != "info" || e.V != 1 {
		t.Fatalf("grouped event: %+v", e)
	}

	evs = nil
	for i := 0; i < 150; i++ {
		evs = append(evs, authEvent{Type: "ssh.login", User: fmt.Sprintf("u%d", i), SourceIP: "10.0.0.2", Method: "publickey",
			At: at, Key: fmt.Sprintf("auth:%d", i)})
	}
	out, dropped = groupAuthEvents(evs, func(authEvent) int { return 0 }, 100)
	if len(out) != 100 || dropped != 50 {
		t.Fatalf("150 distinct logins, cap 100: %d events, %d dropped", len(out), dropped)
	}
}

func TestEventTitles(t *testing.T) {
	at := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		ev    authEvent
		title string
	}{
		{authEvent{Type: "ssh.login", User: "alice", SourceIP: "203.0.113.7"}, "alice logged in over SSH from 203.0.113.7"},
		{authEvent{Type: "rdp.login", User: `CORP\alice`, SourceIP: "203.0.113.7"}, `CORP\alice logged in over Remote Desktop from 203.0.113.7`},
		{authEvent{Type: "console.login", User: "alice"}, "alice signed in at the console"},
		{authEvent{Type: "network.login", User: "svc", SourceIP: "203.0.113.7"}, "svc logged in over the network from 203.0.113.7"},
		{authEvent{Type: "account.created", User: "bob"}, "New account bob"},
		{authEvent{Type: "account.admin_granted", User: "bob", Group: "sudo"}, "bob added to sudo"},
		{authEvent{Type: "audit.log_cleared", By: "Administrator"}, "Security log cleared by Administrator"},
	} {
		c.ev.At, c.ev.Key = at, "k"
		out, _ := groupAuthEvents([]authEvent{c.ev}, func(authEvent) int { return 0 }, 100)
		if len(out) != 1 || out[0].Title != c.title {
			t.Errorf("%s: %+v", c.ev.Type, out)
		}
		if _, has := out[0].Labels["prior_failures"]; has != (c.ev.SourceIP != "") {
			t.Errorf("%s: prior_failures present = %v", c.ev.Type, has)
		}
		if strings.Contains(out[0].Title, "  ") {
			t.Errorf("%s: double space in %q", c.ev.Type, out[0].Title)
		}
	}
}

// Failures in the hour before a login count even when they fall more than an
// hour before the end of the collection window: pruning must not run first.
func TestPriorFailuresSurviveTheWindowEnd(t *testing.T) {
	dir := t.TempDir()
	c := NewAuthCollector("t", WithSpoolDir(dir))
	now := time.Now()
	for i := 0; i < 5; i++ {
		c.failures.add("203.0.113.9", now.Add(-65*time.Minute+time.Duration(i)*time.Second))
	}
	login := authEvent{Type: "ssh.login", User: "root", SourceIP: "203.0.113.9", Method: "password",
		At: now.Add(-9 * time.Minute), Key: "auth:x"}
	var out []metrics.Metric
	if !c.emitEvents(&out, []authEvent{login}, now) {
		t.Fatal("events not written")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "events", "*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("spool files %v", files)
	}
	body, _ := os.ReadFile(files[0])
	if !strings.Contains(string(body), `"prior_failures":"5"`) {
		t.Fatalf("spool line: %s", body)
	}
}
