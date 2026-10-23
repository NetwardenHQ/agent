//go:build !linux && !windows

package security

import (
	"context"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Enabled reports false where there is no log source the collector reads:
// Linux has journald or auth.log (auth_linux.go), Windows the Security event
// log (auth_windows.go).
func (c *AuthCollector) Enabled() bool {
	return false
}

// Collect is a no-op on non-Linux platforms.
func (c *AuthCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	return nil, nil
}
