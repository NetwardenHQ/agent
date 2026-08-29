//go:build !linux

package security

import (
	"context"

	"netwarden/internal/metrics"
)

// Enabled returns false on non-Linux builds. dpkg/rpm have no equivalent on
// macOS or Windows; the platform CVE matcher only consumes Linux package
// snapshots.
func (c *PackagesCollector) Enabled() bool {
	return false
}

// Collect is a no-op on non-Linux platforms.
func (c *PackagesCollector) Collect(_ context.Context) ([]metrics.Metric, error) {
	c.logger.Debug("packages collector skipped (non-linux build)")
	return nil, nil
}
