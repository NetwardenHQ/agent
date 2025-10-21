//go:build !windows
// +build !windows

package postgresql

import (
	"fmt"
	"os"
	"os/exec"
)

// detectPostgreSQL checks if PostgreSQL is running on Unix/Linux.
func (c *Collector) detectPostgreSQL() bool {
	// Check for running PostgreSQL process
	cmd := exec.Command("pgrep", "-x", "postgres")
	if err := cmd.Run(); err != nil {
		c.logger.Debug("no PostgreSQL process found")
		return false
	}

	// Process is running, now find the socket
	if c.config.PostgreSQLSocket != "" {
		// User specified socket path
		if _, err := os.Stat(c.config.PostgreSQLSocket); err == nil {
			c.detectedSocket = c.config.PostgreSQLSocket
			c.logger.Info("using configured PostgreSQL socket", "path", c.detectedSocket)
			return true
		}
	}

	// Auto-detect socket directory
	for _, socketDir := range c.socketPaths {
		// PostgreSQL sockets are named .s.PGSQL.PORT
		socketFile := fmt.Sprintf("%s/.s.PGSQL.5432", socketDir)
		if _, err := os.Stat(socketFile); err == nil {
			c.detectedSocket = socketDir
			c.logger.Info("detected PostgreSQL socket", "path", socketDir)
			return true
		}
	}

	c.logger.Info("PostgreSQL process detected, enabling monitoring")
	return true
}

// checkProcess checks if PostgreSQL process is running on Unix/Linux.
func (c *Collector) checkProcess() bool {
	cmd := exec.Command("pgrep", "-x", "postgres")
	return cmd.Run() == nil
}
