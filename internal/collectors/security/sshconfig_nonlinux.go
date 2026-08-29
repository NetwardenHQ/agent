//go:build !linux && !darwin && !windows

package security

import (
	"context"

	"netwarden/internal/metrics"
)

// Enabled reports false on platforms with no sshd_config implementation.
// Linux, macOS, and Windows are handled by sshconfig_impl.go; this stub
// covers everything else.
func (c *SSHConfigCollector) Enabled() bool {
	return false
}

// Collect is a no-op on unsupported platforms.
func (c *SSHConfigCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	return nil, nil
}
