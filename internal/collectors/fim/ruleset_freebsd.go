//go:build freebsd

package fim

const rulesetRevision = 1

// defaultRoots for FreeBSD and its appliance derivatives (OPNsense, pfSense):
// the base system and ports binaries, authentication and remote-access
// configuration, and scheduled-task files. /conf/config.xml is the whole
// OPNsense configuration; on plain FreeBSD it does not exist and is skipped.
// The credential scope leaves out the binaries and config.xml: OPNsense
// rewrites the latter on every save in its web UI, and its plugin already
// reports configuration changes as events.
func defaultRoots(scope Scope) []string {
	credentials := []string{
		"/etc/sudoers", "/usr/local/etc/sudoers", "/usr/local/etc/sudoers.d",
		"/etc/pam.d",
		"/etc/ssh/sshd_config",
		"/etc/passwd", "/etc/master.passwd", "/etc/group",
		"/etc/rc.conf", "/etc/rc.conf.d", "/boot/loader.conf",
		"/etc/crontab", "/var/cron/tabs",
	}
	if scope != ScopeFull {
		return credentials
	}
	full := append([]string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}, credentials...)
	return append(full, "/conf/config.xml")
}
