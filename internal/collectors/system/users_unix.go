//go:build !windows
// +build !windows

package system

import (
	"context"
	"errors"
	"os"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/process"
)

// getWindowsUserCount is not used on Unix systems
func getWindowsUserCount(ctx context.Context) (int, error) {
	// This function is only for Windows
	return 0, nil
}

// getWindowsProcessCount is not used on Unix systems
func getWindowsProcessCount(ctx context.Context) (int, error) {
	// This function is only for Windows
	return 0, nil
}

// getUnixUserCount gets the count of logged-in users on Unix/Linux
func getUnixUserCount(ctx context.Context) (int, error) {
	// Use gopsutil which works well on Unix/Linux
	users, err := host.UsersWithContext(ctx)
	if err != nil {
		// Ubuntu 25.10+ and modern systemd removed /var/run/utmp for Y2038 compliance
		// Silently return 0 instead of error when file doesn't exist (expected behavior)
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	return len(users), nil
}

// getUnixProcessCount gets the count of running processes on Unix/Linux
func getUnixProcessCount(ctx context.Context) (int, error) {
	// Use gopsutil which works well on Unix/Linux
	pids, err := process.PidsWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return len(pids), nil
}
