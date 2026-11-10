//go:build !linux && !windows

package procscan

import (
	"context"
	"os/exec"
	"time"
)

// Running reports whether a process named one of names is running.
func Running(names ...string) bool {
	for _, name := range names {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := exec.CommandContext(ctx, "pgrep", "-x", name).Run()
		cancel()
		if err == nil {
			return true
		}
	}
	return false
}
