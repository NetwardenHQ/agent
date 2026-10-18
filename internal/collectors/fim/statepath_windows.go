//go:build windows

package fim

import (
	"os"
	"path/filepath"
)

// defaultManifestPath is the FIM baseline location on Windows: under
// %ProgramData%, the standard place for machine-scoped application state.
func defaultManifestPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "Netwarden", "fim-manifest")
}
