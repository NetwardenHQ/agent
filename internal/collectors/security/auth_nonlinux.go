//go:build !linux && !windows && !freebsd

package security

import (
	"context"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Enabled reports false where there is no log source the collector reads:
// Linux and FreeBSD have journald or auth.log (auth_unix.go), Windows the
// Security event log (auth_windows.go).
func (c *AuthCollector) Enabled() bool {
	return false
}

// Collect is a no-op where there is no source (macOS and others).
func (c *AuthCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	return nil, nil
}
