//go:build windows

package security

import (
	"os"
	"path/filepath"
)

// sshdConfigPath returns the Windows OpenSSH server config location.
//
// The Windows port of OpenSSH keeps its configuration in %ProgramData%\ssh
// rather than /etc/ssh. ProgramData is resolved from the environment because
// it is relocatable, falling back to the near-universal default when unset.
// The directive syntax itself is identical to Unix, so the shared parser
// applies unchanged.
func sshdConfigPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "ssh", "sshd_config")
}
