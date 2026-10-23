//go:build windows

package fim

import (
	"os"
	"path/filepath"
)

const rulesetRevision = 1

// defaultRoots for Windows: the file-based persistence and integrity surfaces
// that matter, kept tight. Registry-based persistence (Run keys, service
// definitions) is out of scope for a file-hashing FIM; it needs a registry
// monitor.
//
// System32 as a whole is deliberately excluded: it holds thousands of DLLs
// that legitimately churn on Windows Update and would bury real signal. The
// narrow, high-signal paths below are the equivalent of the Unix
// cron/systemd/sudoers set.
//
// The list is already narrow, so both scopes watch all of it.
func defaultRoots(Scope) []string {
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}

	return []string{
		// hosts, networks, services, protocol: network redirection.
		filepath.Join(sys, `System32\drivers\etc`),
		// Scheduled tasks: the primary file-based persistence surface.
		filepath.Join(sys, `System32\Tasks`),
		// Local Group Policy: silent policy tampering.
		filepath.Join(sys, `System32\GroupPolicy`),
		// All-users startup folder.
		filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\StartUp`),
	}
}
