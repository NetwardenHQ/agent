//go:build linux || darwin

package security

// sshdConfigPath returns the OpenSSH server config location. Linux and macOS
// both use the standard /etc/ssh path.
func sshdConfigPath() string {
	return "/etc/ssh/sshd_config"
}
