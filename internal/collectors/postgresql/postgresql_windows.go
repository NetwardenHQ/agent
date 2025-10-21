//go:build windows
// +build windows

package postgresql

import (
	"os/exec"
	"strings"
)

// detectPostgreSQL checks if PostgreSQL is running on Windows.
func (c *Collector) detectPostgreSQL() bool {
	// Check for PostgreSQL using PowerShell
	psScript := `Get-Process -Name 'postgres' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		c.logger.Debug("no PostgreSQL process found on Windows")
		return false
	}

	processName := strings.TrimSpace(string(output))
	if processName == "" {
		return false
	}

	c.logger.Info("PostgreSQL process detected on Windows", "process", processName)

	// On Windows, PostgreSQL typically uses TCP connection
	// Default to localhost:5432
	c.isWindows = true
	return true
}

// checkProcess checks if PostgreSQL process is running on Windows.
func (c *Collector) checkProcess() bool {
	psScript := `Get-Process -Name 'postgres' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	err := cmd.Run()
	return err == nil
}
