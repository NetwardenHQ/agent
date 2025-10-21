//go:build windows
// +build windows

package mysql

import (
	"os/exec"
	"strings"
)

// detectMySQL checks if MySQL/MariaDB is running on Windows.
func (c *Collector) detectMySQL() bool {
	// Check for MySQL/MariaDB using PowerShell
	psScript := `Get-Process -Name 'mysqld','mariadbd' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		c.logger.Debug("no MySQL/MariaDB process found on Windows")
		return false
	}

	processName := strings.TrimSpace(string(output))
	if processName == "" {
		return false
	}

	c.logger.Info("MySQL/MariaDB process detected on Windows", "process", processName)

	// On Windows, MySQL typically uses TCP connection, not Unix socket
	// Set up for TCP connection to localhost:3306
	c.isWindows = true
	return true
}

// checkProcess checks if MySQL/MariaDB process is running on Windows.
func (c *Collector) checkProcess() bool {
	psScript := `Get-Process -Name 'mysqld','mariadbd' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	err := cmd.Run()
	return err == nil
}
