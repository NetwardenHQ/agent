//go:build !windows
// +build !windows

package process

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// getProcessStats gets statistics for a running process on Unix/Linux systems.
func (c *Collector) getProcessStats(processName string) *ProcessStats {
	// First, find the PID using pgrep
	cmd := exec.Command("pgrep", "-f", processName)
	output, err := cmd.Output()
	if err != nil {
		// Process not found
		return nil
	}

	// Parse PIDs (pgrep can return multiple)
	pids := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pids) == 0 || pids[0] == "" {
		return nil
	}

	// Use the first PID found
	pid, err := strconv.Atoi(pids[0])
	if err != nil {
		c.logger.Debug("failed to parse PID", "pid", pids[0], "error", err)
		return nil
	}

	stats := &ProcessStats{
		PID: pid,
	}

	// Get CPU and memory stats from /proc/[pid]/stat and /proc/[pid]/status
	if err := c.readProcStats(pid, stats); err != nil {
		c.logger.Debug("failed to read proc stats", "pid", pid, "error", err)
		// Return partial stats with just PID
		return stats
	}

	return stats
}

// readProcStats reads CPU and memory statistics from /proc filesystem.
func (c *Collector) readProcStats(pid int, stats *ProcessStats) error {
	// Read memory from /proc/[pid]/status
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		return err
	}

	// Parse VmRSS (resident set size) for memory usage
	lines := strings.Split(string(statusData), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memKB, err := strconv.ParseFloat(fields[1], 64)
				if err == nil {
					stats.MemoryMB = memKB / 1024 // Convert KB to MB
				}
			}
			break
		}
	}

	// Read CPU from /proc/[pid]/stat
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return err
	}

	// Parse CPU times from /proc/[pid]/stat (fields 13-14: utime, stime)
	statStr := string(statData)
	lastParen := strings.LastIndex(statStr, ")")
	if lastParen == -1 {
		return fmt.Errorf("invalid stat format")
	}

	fieldsStr := statStr[lastParen+1:]
	fields := strings.Fields(fieldsStr)
	if len(fields) < 13 {
		return fmt.Errorf("insufficient fields in stat file")
	}

	utime, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse utime: %w", err)
	}

	stime, err := strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse stime: %w", err)
	}

	totalTime := utime + stime
	clockTicks := int64(100) // Standard clock ticks per second on Linux
	cpuSeconds := float64(totalTime) / float64(clockTicks)
	stats.CPUPercent = cpuSeconds // CPU time in seconds (not percentage)

	return nil
}
