//go:build !linux && !windows

package process

import (
	"context"
	"strings"
	"time"

	gopsprocess "github.com/shirou/gopsutil/v4/process"
)

// getProcessStats finds the lowest-numbered process whose command line
// contains processName and returns its stats, or nil if none is running.
// Platforms without procfs (macOS, the BSDs) go through gopsutil, which
// reads the kernel's process table directly.
func (c *Collector) getProcessStats(processName string) *ProcessStats {
	if processName == "" {
		return nil // an empty needle is in every command line
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pids, err := gopsprocess.PidsWithContext(ctx)
	if err != nil {
		c.logger.Debug("failed to list processes", "error", err)
		return nil
	}

	var found *gopsprocess.Process
	for _, pid := range pids {
		if found != nil && pid > found.Pid {
			continue
		}
		p, err := gopsprocess.NewProcessWithContext(ctx, pid)
		if err != nil {
			continue
		}
		cmdline, err := p.CmdlineWithContext(ctx)
		if err != nil || !strings.Contains(cmdline, processName) {
			continue
		}
		found = p
	}
	if found == nil {
		return nil
	}

	stats := &ProcessStats{PID: int(found.Pid)}
	if times, err := found.TimesWithContext(ctx); err == nil {
		stats.CPUTime = time.Duration((times.User + times.System) * float64(time.Second))
		stats.CPUKnown = true
	} else {
		c.logger.Debug("failed to read process CPU time", "pid", found.Pid, "error", err)
	}
	if mem, err := found.MemoryInfoWithContext(ctx); err == nil {
		stats.MemoryMB = float64(mem.RSS) / 1048576.0
		stats.MemoryKnown = true
	} else {
		c.logger.Debug("failed to read process memory", "pid", found.Pid, "error", err)
	}
	return stats
}
