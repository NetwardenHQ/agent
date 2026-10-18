//go:build linux

package process

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// clockTicksPerSecond is the kernel's USER_HZ, the unit of the utime/stime
// fields in /proc/<pid>/stat. It is 100 on every Linux architecture Go
// targets; the kernel exposes it only through sysconf(_SC_CLK_TCK), which a
// CGO-free binary cannot call.
const clockTicksPerSecond = 100

var errInvalidStat = errors.New("unexpected /proc/<pid>/stat format")

// getProcessStats finds the lowest-numbered process whose command line
// contains processName and returns its stats, or nil if none is running.
//
// It walks /proc rather than exec'ing pgrep, which would cost a fork+exec
// per monitored process per cycle. The match is a plain substring match
// against the full command line.
func (c *Collector) getProcessStats(processName string) *ProcessStats {
	pid := findPID(processName)
	if pid <= 0 {
		return nil
	}

	stats := &ProcessStats{PID: pid}
	if err := c.readProcStats(pid, stats); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // exited between the scan and the read
		}
		c.logger.Debug("failed to read proc stats", "pid", pid, "error", err)
	}
	return stats
}

// findPID returns the lowest PID (other than our own) whose command line
// contains name, or 0.
func findPID(name string) int {
	if name == "" {
		return 0 // an empty needle is in every command line
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	self := os.Getpid()
	needle := []byte(name)

	best := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		if best != 0 && pid > best {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(cmdline) == 0 {
			continue // exited, or a kernel thread with no command line
		}
		if bytes.Contains(cmdline, needle) {
			best = pid
		}
	}
	return best
}

// readProcStats fills memory and cumulative CPU time from /proc/<pid>,
// setting MemoryKnown / CPUKnown for each figure it actually read.
func (c *Collector) readProcStats(pid int, stats *ProcessStats) error {
	dir := filepath.Join("/proc", strconv.Itoa(pid))

	status, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			if fields := strings.Fields(rest); len(fields) >= 1 {
				if kb, err := strconv.ParseFloat(fields[0], 64); err == nil {
					stats.MemoryMB, stats.MemoryKnown = kb/1024, true
				}
			}
			break
		}
	}

	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return err
	}
	// The command name in field 2 is parenthesized and may itself contain
	// spaces or parentheses, so the fields are read after the last ')'.
	statStr := string(stat)
	lastParen := strings.LastIndexByte(statStr, ')')
	if lastParen < 0 {
		return errInvalidStat
	}
	fields := strings.Fields(statStr[lastParen+1:])
	// After the ')' the fields are state(0) ppid(1) ... utime(11) stime(12).
	if len(fields) < 13 {
		return errInvalidStat
	}
	utime, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return err
	}
	stime, err := strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return err
	}
	stats.CPUTime = time.Duration(utime+stime) * time.Second / clockTicksPerSecond
	stats.CPUKnown = true
	return nil
}
