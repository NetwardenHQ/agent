//go:build darwin

package fim

const rulesetRevision = 1

// defaultRoots for macOS: the Unix-family sensitive paths that exist on a Mac.
func defaultRoots() []string {
	return []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
		"/etc/sudoers", "/etc/sudoers.d",
		"/etc/pam.d",
		"/etc/ssh/sshd_config",
		"/etc/passwd", "/etc/group",
		"/Library/LaunchDaemons", "/Library/LaunchAgents",
		"/etc/crontab",
	}
}
