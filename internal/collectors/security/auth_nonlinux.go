//go:build !linux

package security

import (
	"context"

	"netwarden/internal/metrics"
)

// Enabled reports false on non-Linux platforms — failed-login monitoring
// requires journald or syslog-style auth logs.
func (c *AuthCollector) Enabled() bool {
	return false
}

// Collect is a no-op on non-Linux platforms.
func (c *AuthCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	return nil, nil
}
