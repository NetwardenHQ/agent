//go:build linux

package fim

// rulesetRevision is bumped whenever the default watched-path set changes. A
// baseline built under another revision is rebuilt, with rebuild_reason
// "ruleset_changed", rather than diffed into a storm of creates and deletes.
const rulesetRevision = 1

// defaultRoots is the tight, high-signal set for Linux: the paths whose
// modification is almost always part of an intrusion, not routine operation.
// It is deliberately narrow: wide coverage (all of /etc, web roots) is noisier
// and belongs in operator-configured roots (fim_roots). The credential scope
// leaves out the binary directories, the only part that is costly to hash.
func defaultRoots(scope Scope) []string {
	credentials := []string{
		// Privilege and authentication configuration.
		"/etc/sudoers", "/etc/sudoers.d",
		"/etc/pam.d",
		"/etc/ssh/sshd_config",
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		// Persistence surfaces.
		"/etc/systemd/system",
		"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
		"/etc/cron.weekly", "/etc/cron.monthly", "/etc/crontab",
		"/etc/rc.local",
	}
	if scope != ScopeFull {
		return credentials
	}
	// System binaries: the primary rootkit target.
	return append([]string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}, credentials...)
}
