//go:build freebsd

package security

import (
	"os"
	"path/filepath"
)

// sshdConfigPath returns the config of the sshd that runs on this host.
// FreeBSD's base sshd reads /etc/ssh/sshd_config. OPNsense, and FreeBSD hosts
// running the security/openssh-portable port, run /usr/local/sbin/sshd, which
// reads /usr/local/etc/ssh/sshd_config.
func sshdConfigPath() string { return freebsdSSHDConfigPath("/") }

func freebsdSSHDConfigPath(root string) string {
	port := filepath.Join(root, "usr/local/etc/ssh/sshd_config")
	if isFile(filepath.Join(root, "usr/local/sbin/sshd")) && isFile(port) {
		return port
	}
	return filepath.Join(root, "etc/ssh/sshd_config")
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
