//go:build !linux && !darwin && !windows && !freebsd

package security

import (
	"context"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Enabled returns false on platforms with no listening-socket
// implementation. Linux uses ss/netstat (ports_linux.go), FreeBSD sockstat,
// and macOS and Windows gopsutil (ports_gopsutil.go).
func (c *PortsCollector) Enabled() bool {
	return false
}

// Collect is a no-op on unsupported platforms.
func (c *PortsCollector) Collect(_ context.Context) ([]metrics.Metric, error) {
	c.logger.Debug("ports collector skipped (unsupported platform)")
	return nil, nil
}
