package security

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/NetwardenHQ/agent/internal/spool"
)

// Security events: logins, new accounts and new administrators, sent one by
// one (unlike failed logins, which stay counts) through the agent's spool, so
// they are delivered at least once and survive a restart or an outage. The
// platform turns a few of them into findings. Contract: docs/spool.md.
//
// A failed login never becomes an event: people type their password into
// the username field, and that must not leave the host.

// authEvent is one login or account change, before grouping.
type authEvent struct {
	Type     string // ssh.login, rdp.login, console.login, network.login, account.created, account.admin_granted, audit.log_cleared
	User     string
	SourceIP string
	Method   string // ssh: publickey, password, ...
	KeyFP    string // ssh: the key's fingerprint, for publickey
	Auth     string // windows network logons: NTLM, Kerberos, ...
	Group    string
	By       string
	At       time.Time
	Key      string // dedupe_key: "auth:<hash of the log line>" or "win:<EventRecordID>"
}

// maxEventGroups bounds what one collection writes: identical events are
// folded first, so this is reached only by a burst of distinct ones. The
// rest are counted in security_events_dropped.
const maxEventGroups = 100

// failureWindow is how far back a login looks for failures from its source.
const failureWindow = time.Hour

// adminGroups are the Unix groups that grant root through sudo.
var adminGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true}

var (
	// "Accepted publickey for deploy from 198.51.100.4 port 51122 ssh2: ED25519 SHA256:abc"
	// Certificate logins append more after the fingerprint ("ID ... serial ...").
	acceptedRe = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+(?: \S+?)?(?:: \S+ (\S+).*)?$`)
	// useradd: "new user: name=bob, UID=1001, GID=1001, home=/home/bob, ..."
	newUserRe = regexp.MustCompile(`^new user: name=([^,]+),`)
	// usermod -aG: "add 'bob' to group 'sudo'" (and a "shadow group" twin, ignored)
	usermodAddRe = regexp.MustCompile(`^add '([^']+)' to group '([^']+)'$`)
	// gpasswd -a: "user bob added by root to group wheel"
	gpasswdAddRe = regexp.MustCompile(`^user (\S+) added by (\S+) to group (\S+)$`)
)

// parseAuthMessage reads the message part of a log line (after "prog[pid]: ")
// and reports the login or account change it records, if any. It never looks
// at the program name: OpenSSH 9.8 logs sessions from sshd-session.
func parseAuthMessage(msg string) (authEvent, bool) {
	msg = strings.TrimSpace(msg)
	if m := acceptedRe.FindStringSubmatch(msg); m != nil {
		return authEvent{Type: "ssh.login", Method: m[1], User: m[2], SourceIP: m[3], KeyFP: m[4]}, true
	}
	if m := newUserRe.FindStringSubmatch(msg); m != nil {
		return authEvent{Type: "account.created", User: m[1]}, true
	}
	if m := usermodAddRe.FindStringSubmatch(msg); m != nil && adminGroups[m[2]] {
		return authEvent{Type: "account.admin_granted", User: m[1], Group: m[2]}, true
	}
	if m := gpasswdAddRe.FindStringSubmatch(msg); m != nil && adminGroups[m[3]] {
		return authEvent{Type: "account.admin_granted", User: m[1], By: m[2], Group: m[3]}, true
	}
	return authEvent{}, false
}

// messageOf is the text after the first ": " of a syslog or journal line,
// which ends the "prog[pid]" tag in every timestamp format the collector
// reads (their colons are never followed by a space).
func messageOf(line string) string {
	if _, msg, ok := strings.Cut(line, ": "); ok {
		return msg
	}
	return ""
}

// lineKey is the dedupe_key of an event read from a log line: the line holds
// its own timestamp, so the same line read twice gives the same key.
func lineKey(line string) string {
	sum := sha256.Sum256([]byte(line))
	return "auth:" + hex.EncodeToString(sum[:])[:32]
}

// failureLog remembers when each source address failed to log in during the
// last hour, so a login can say how many failures came before it. It is
// in-memory: a restart forgets it, and the platform also checks the failed-
// login metrics of every host in the account.
type failureLog struct {
	byIP  map[string][]time.Time
	maxIP int
}

func newFailureLog(maxIP int) *failureLog {
	return &failureLog{byIP: map[string][]time.Time{}, maxIP: maxIP}
}

func (f *failureLog) add(ip string, at time.Time) {
	if _, ok := f.byIP[ip]; !ok && len(f.byIP) >= f.maxIP {
		f.evictOldest()
	}
	f.byIP[ip] = append(f.byIP[ip], at)
}

// before counts failures from ip in the hour before at.
func (f *failureLog) before(ip string, at time.Time) int {
	n := 0
	for _, t := range f.byIP[ip] {
		if t.Before(at) && !t.Before(at.Add(-failureWindow)) {
			n++
		}
	}
	return n
}

// prune drops failures older than the window that ends at now.
func (f *failureLog) prune(now time.Time) {
	cutoff := now.Add(-failureWindow)
	for ip, ts := range f.byIP {
		kept := ts[:0]
		for _, t := range ts {
			if !t.Before(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(f.byIP, ip)
		} else {
			f.byIP[ip] = kept
		}
	}
}

func (f *failureLog) evictOldest() {
	var oldestIP string
	var oldest time.Time
	for ip, ts := range f.byIP {
		last := ts[len(ts)-1]
		if oldestIP == "" || last.Before(oldest) {
			oldestIP, oldest = ip, last
		}
	}
	delete(f.byIP, oldestIP)
}

// groupAuthEvents folds identical events (same type, account, source and
// method) into one with a count, in order of first occurrence, and turns
// them into spool events. prior gives a login's failures from its source in
// the hour before it. At most max groups are returned; the rest are counted.
func groupAuthEvents(evs []authEvent, prior func(authEvent) int, max int) ([]spool.Event, int) {
	type group struct {
		first authEvent
		count int
	}
	var order []string
	groups := map[string]*group{}
	for _, e := range evs {
		k := strings.Join([]string{e.Type, e.User, e.SourceIP, e.Method, e.KeyFP, e.Auth, e.Group, e.By}, "\x00")
		if g, ok := groups[k]; ok {
			g.count++
			continue
		}
		groups[k] = &group{first: e, count: 1}
		order = append(order, k)
	}

	dropped := 0
	if len(order) > max {
		dropped = len(order) - max
		order = order[:max]
	}
	out := make([]spool.Event, 0, len(order))
	for _, k := range order {
		g := groups[k]
		e := g.first
		labels := map[string]string{"count": strconv.Itoa(g.count)}
		for name, v := range map[string]string{
			"user": e.User, "source_ip": e.SourceIP, "method": e.Method, "key_fp": e.KeyFP,
			"auth": e.Auth, "group": e.Group, "by": e.By,
		} {
			if v != "" {
				labels[name] = v
			}
		}
		if e.SourceIP != "" && strings.HasSuffix(e.Type, ".login") {
			labels["prior_failures"] = strconv.Itoa(prior(e))
		}
		title := eventTitle(e)
		if g.count > 1 {
			title += " (" + strconv.Itoa(g.count) + " times)"
		}
		out = append(out, spool.Event{
			V:          1,
			Type:       e.Type,
			Severity:   "info",
			Title:      truncateRunes(title, 200),
			OccurredAt: e.At.UTC().Format(time.RFC3339),
			DedupeKey:  e.Key,
			Labels:     labels,
		})
	}
	return out, dropped
}

func eventTitle(e authEvent) string {
	switch e.Type {
	case "ssh.login":
		return e.User + " logged in over SSH from " + e.SourceIP
	case "rdp.login":
		return e.User + " logged in over Remote Desktop from " + e.SourceIP
	case "console.login":
		return e.User + " signed in at the console"
	case "network.login":
		return e.User + " logged in over the network from " + e.SourceIP
	case "account.created":
		return "New account " + e.User
	case "account.admin_granted":
		return e.User + " added to " + e.Group
	case "audit.log_cleared":
		if e.By == "" {
			return "Security log cleared"
		}
		return "Security log cleared by " + e.By
	}
	return e.Type
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
