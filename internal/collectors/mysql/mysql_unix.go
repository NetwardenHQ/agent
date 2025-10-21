//go:build !windows
// +build !windows

package mysql

import (
	"os"
	"os/exec"
)

// detectMySQL checks if MySQL/MariaDB is running on Unix/Linux.
func (c *Collector) detectMySQL() bool {
	// Check for running MySQL/MariaDB processes
	cmd := exec.Command("pgrep", "-x", "mysqld")
	if err := cmd.Run(); err != nil {
		// Also check for mariadb process name
		cmd = exec.Command("pgrep", "-x", "mariadbd")
		if err := cmd.Run(); err != nil {
			c.logger.Debug("no MySQL/MariaDB process found")
			return false
		}
	}

	// Process is running, now find the socket
	if c.config.MySQLSocket != "" {
		// User specified socket path
		if _, err := os.Stat(c.config.MySQLSocket); err == nil {
			c.detectedSocket = c.config.MySQLSocket
			c.logger.Info("using configured MySQL socket", "path", c.detectedSocket)
			return true
		}
	}

	// Auto-detect socket path
	for _, socketPath := range c.socketPaths {
		if _, err := os.Stat(socketPath); err == nil {
			c.detectedSocket = socketPath
			c.logger.Info("detected MySQL socket", "path", socketPath)
			return true
		}
	}

	c.logger.Debug("MySQL process found but no socket detected")
	return false
}

// checkProcess checks if MySQL/MariaDB process is running on Unix/Linux.
func (c *Collector) checkProcess() bool {
	cmd := exec.Command("pgrep", "-x", "mysqld")
	if err := cmd.Run(); err == nil {
		return true
	}
	cmd = exec.Command("pgrep", "-x", "mariadbd")
	return cmd.Run() == nil
}
