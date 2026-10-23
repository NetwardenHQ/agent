//go:build darwin

package fim

const rulesetRevision = 1

// defaultRoots for macOS: the Unix-family sensitive paths that exist on a Mac.
// The credential scope leaves out the binary directories.
func defaultRoots(scope Scope) []string {
	credentials := []string{
		"/etc/sudoers", "/etc/sudoers.d",
		"/etc/pam.d",
		"/etc/ssh/sshd_config",
		"/etc/passwd", "/etc/group",
		"/Library/LaunchDaemons", "/Library/LaunchAgents",
		"/etc/crontab",
	}
	if scope != ScopeFull {
		return credentials
	}
	return append([]string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"}, credentials...)
}
