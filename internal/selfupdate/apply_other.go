//go:build !windows && !linux && !darwin && !freebsd

package selfupdate

import (
	"context"
	"errors"
	"log/slog"
)

func platformSupport() Support {
	return Support{Reason: "self-update is not available on this platform"}
}

func applyUpdate(_ context.Context, _ Target, _ []string, _ *slog.Logger) error {
	return errors.New("self-update is not available on this platform")
}
