//go:build !windows
// +build !windows

package postgresql

import (
	"fmt"
	"os"

	"github.com/NetwardenHQ/agent/internal/dsm"
	"github.com/NetwardenHQ/agent/internal/procscan"
)

// detectPostgreSQL checks if PostgreSQL is running on Unix/Linux.
func (c *Collector) detectPostgreSQL() bool {
	if !c.ownedByUser() {
		c.logger.Debug("PostgreSQL on DSM belongs to DSM; set postgresql_host or postgresql_socket to monitor one of your own")
		return false
	}
	if !procscan.Running("postgres") {
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
	return procscan.Running("postgres")
}

// ownedByUser reports whether a running PostgreSQL is one the owner runs.
// DSM starts its own for Synology's apps, reachable only by DSM itself; on
// DSM the agent watches a PostgreSQL only when the config names one.
func (c *Collector) ownedByUser() bool {
	if !dsm.Is() {
		return true
	}
	return c.config.PostgreSQLHost != "" || c.config.PostgreSQLSocket != "" || c.config.PostgreSQLUser != ""
}
