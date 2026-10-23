//go:build linux || darwin || freebsd

package selfupdate

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"
)

// restartGrace is how long the agent waits to be replaced after starting a
// package upgrade. apt, dnf and pkg(8) finish well inside it.
const restartGrace = 15 * time.Minute

// awaitReplacement waits for the upgrade to stop this process. Shutdown
// cancels ctx, which is the expected outcome. Still running when the timer
// fires means the upgrade failed somewhere the agent cannot see, and where
// says where to look.
func awaitReplacement(ctx context.Context, target Target, within time.Duration, where string) error {
	timer := time.NewTimer(within)
	defer timer.Stop()
	select {
	case <-timer.C:
		return fmt.Errorf("still running %s %s after starting the upgrade to %s; see %s",
			target.Current, within, target.Version, where)
	case <-ctx.Done():
		return nil
	}
}

// restartSelf asks this process to shut down cleanly, as the service manager
// would. launchd and the kubelet start it again.
func restartSelf() error {
	return syscall.Kill(os.Getpid(), syscall.SIGTERM)
}
