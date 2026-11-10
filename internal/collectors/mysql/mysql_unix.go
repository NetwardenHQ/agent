//go:build !windows
// +build !windows

package mysql

import (
	"os"

	"github.com/NetwardenHQ/agent/internal/procscan"
)

// detectMySQL checks if MySQL/MariaDB is running on Unix/Linux.
func (c *Collector) detectMySQL() bool {
	if !procscan.Running("mysqld", "mariadbd") {
		c.logger.Debug("no MySQL/MariaDB process found")
		return false
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
	return procscan.Running("mysqld", "mariadbd")
}
