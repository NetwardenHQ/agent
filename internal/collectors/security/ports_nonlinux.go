//go:build !linux && !darwin && !windows

package security

import (
	"context"

	"netwarden/internal/metrics"
)

// Enabled returns false on platforms with no listening-socket
// implementation. Linux uses ss/netstat (ports_linux.go); macOS and Windows
// use gopsutil (ports_gopsutil.go). Everything else — the BSDs, Solaris,
// AIX — falls through to this stub.
func (c *PortsCollector) Enabled() bool {
	return false
}

// Collect is a no-op on unsupported platforms.
func (c *PortsCollector) Collect(_ context.Context) ([]metrics.Metric, error) {
	c.logger.Debug("ports collector skipped (unsupported platform)")
	return nil, nil
}
