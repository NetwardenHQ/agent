//go:build !windows

package selfupdate

import (
	"context"
	"errors"
	"log/slog"
)

// applyUpdate is a no-op off Windows.
//
// Linux hosts upgrade through apt or yum: the packages already install the
// Netwarden signing key and register the repository with gpgcheck enabled, and
// the systemd unit sets ProtectSystem=strict with write access limited to
// /var/log/netwarden and /etc/netwarden, so the agent cannot replace
// /usr/bin/netwarden even as root. That restriction is deliberate; running
// `apt-get install --only-upgrade netwarden` from a timer achieves the same
// result without giving the agent write access to itself.
func applyUpdate(_ context.Context, _ Target, _ []string, _ *slog.Logger) error {
	return errors.New("self-update is not implemented on this platform")
}
