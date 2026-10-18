//go:build freebsd

package fim

const rulesetRevision = 1

// defaultRoots for FreeBSD and its appliance derivatives (OPNsense, pfSense):
// the base system and ports binaries, authentication and remote-access
// configuration, and scheduled-task files. /conf/config.xml is the whole
// OPNsense configuration; on plain FreeBSD it does not exist and is skipped.
func defaultRoots() []string {
	return []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin",
		"/usr/local/bin", "/usr/local/sbin",
		"/etc/sudoers", "/usr/local/etc/sudoers", "/usr/local/etc/sudoers.d",
		"/etc/pam.d",
		"/etc/ssh/sshd_config",
		"/etc/passwd", "/etc/master.passwd", "/etc/group",
		"/etc/rc.conf", "/etc/rc.conf.d", "/boot/loader.conf",
		"/etc/crontab", "/var/cron/tabs",
		"/conf/config.xml",
	}
}
