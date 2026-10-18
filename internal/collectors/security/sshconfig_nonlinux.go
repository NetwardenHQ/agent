//go:build !linux && !darwin && !windows && !freebsd

package security

import (
	"context"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Enabled reports false on platforms with no sshd_config implementation.
// Linux, macOS, FreeBSD and Windows are handled by sshconfig_impl.go.
func (c *SSHConfigCollector) Enabled() bool {
	return false
}

// Collect is a no-op on unsupported platforms.
func (c *SSHConfigCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	return nil, nil
}
