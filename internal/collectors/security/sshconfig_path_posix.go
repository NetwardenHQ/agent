//go:build linux || darwin

package security

// sshdConfigPath returns the OpenSSH server config location.
func sshdConfigPath() string {
	return "/etc/ssh/sshd_config"
}
