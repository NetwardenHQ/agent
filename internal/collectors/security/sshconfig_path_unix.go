//go:build linux || darwin || freebsd

package security

// sshdConfigPath returns the OpenSSH server config location. Linux, macOS and
// FreeBSD all use the standard /etc/ssh path.
func sshdConfigPath() string {
	return "/etc/ssh/sshd_config"
}
