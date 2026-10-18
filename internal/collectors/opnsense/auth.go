package opnsense

import (
	"context"
	"net/netip"
	"regexp"
)

// The patterns are anchored at both ends of the message. The username is
// attacker-chosen and may itself contain " from <ip>", so the address is
// always the one the logging program appended last, never the first match.
var (
	guiFailRe = regexp.MustCompile(`^\S*:? ?Web GUI authentication error for '(.*)' from (\S+)\s*$`)
	guiOKRe   = regexp.MustCompile(`^\S*:? ?Successful login for user '(.*)' from:? (\S+)\s*$`)
	sshFailRe = regexp.MustCompile(`^Failed (?:password|publickey|none|keyboard-interactive/pam) for (?:invalid user )?(.*) from (\S+) port \d+(?: ssh2)?\s*$`)
	sshOKRe   = regexp.MustCompile(`^Accepted \S+ for (.*) from (\S+) port \d+(?: ssh2)?(?:: .*)?\s*$`)
)

// authTally classifies OPNsense's audit log (GUI logins from `audit`, SSH from
// `sshd`). Lines are routed on the syslog program field, never on message
// text an attacker controls. Only "Failed ..." lines count as SSH failures:
// sshd also logs "Invalid user" for the same attempt, and counting both would
// double it. A source that does not parse as an IP address is counted as a
// failure but not as an address.
type authTally struct {
	failGUI, failSSH, okGUI, okSSH int
	users, ips                     map[string]int
}

func newAuthTally() *authTally {
	return &authTally{users: map[string]int{}, ips: map[string]int{}}
}

func (t *authTally) fail(user, ip []byte) {
	t.users[string(user)]++
	if addr, err := netip.ParseAddr(string(ip)); err == nil {
		t.ips[addr.String()]++
	}
}

// add classifies one audit log line.
func (t *authTally) add(l []byte) {
	app, msg, ok := splitSyslog(l)
	if !ok {
		return
	}
	switch string(app) {
	case "audit":
		if m := guiFailRe.FindSubmatch(msg); m != nil {
			t.failGUI++
			t.fail(m[1], m[2])
		} else if guiOKRe.Match(msg) {
			t.okGUI++
		}
	case "sshd":
		if m := sshFailRe.FindSubmatch(msg); m != nil {
			t.failSSH++
			t.fail(m[1], m[2])
		} else if sshOKRe.Match(msg) {
			t.okSSH++
		}
	}
}

// collectAuth emits the same security_failed_logins family the Linux auth
// collector does, so the platform's failed-login views and alerts work for a
// firewall unchanged, plus per-service counts.
func (c *Collector) collectAuth(_ context.Context, e *emitter) error {
	t := newAuthTally()
	skipped, measured, err := c.audit.each(e.ts, t.add)
	if err != nil || !measured {
		return err
	}
	e.gauge("security_failed_logins", float64(t.failGUI+t.failSSH), nil)
	e.gauge("security_failed_logins_unique_users", float64(len(t.users)), nil)
	e.gauge("security_failed_logins_unique_ips", float64(len(t.ips)), nil)
	if top := topN(t.ips, 5); len(top) > 0 {
		labels := snapshotLabels("ip", top)
		labels["source"] = "opnsense-audit"
		e.gauge("security_failed_logins_top_ips", float64(len(top)), labels)
	}
	e.gauge("opnsense_login_failures", float64(t.failGUI), map[string]string{"service": "gui"})
	e.gauge("opnsense_login_failures", float64(t.failSSH), map[string]string{"service": "ssh"})
	e.gauge("opnsense_login_successes", float64(t.okGUI), map[string]string{"service": "gui"})
	e.gauge("opnsense_login_successes", float64(t.okSSH), map[string]string{"service": "ssh"})
	if skipped > 0 {
		e.gauge("opnsense_log_skipped_bytes", float64(skipped), map[string]string{"log": "audit"})
	}
	return nil
}
