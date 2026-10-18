//go:build windows

package process

import (
	"fmt"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
)

// Win32_Process is the subset of the WMI Win32_Process class the collector reads.
type Win32_Process struct {
	Name           string
	ProcessId      uint32
	WorkingSetSize uint64 // Memory in bytes
	KernelModeTime uint64 // CPU time in 100-nanosecond intervals
	UserModeTime   uint64 // CPU time in 100-nanosecond intervals
}

// sanitizeWQLString escapes single quotes to prevent WQL injection.
func sanitizeWQLString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// getProcessStats returns the stats of the first process WMI reports under
// processName (with or without .exe), or nil if none is running. A WMI query
// takes tens of milliseconds, against seconds for a PowerShell call.
func (c *Collector) getProcessStats(processName string) *ProcessStats {
	// WMI matches the image name exactly.
	queryName := processName
	if !strings.HasSuffix(queryName, ".exe") {
		queryName += ".exe"
	}

	// The name comes from the API, so it is escaped before going into WQL.
	safeQueryName := sanitizeWQLString(queryName)

	var processes []Win32_Process
	query := fmt.Sprintf("SELECT Name, ProcessId, WorkingSetSize, KernelModeTime, UserModeTime FROM Win32_Process WHERE Name = '%s'", safeQueryName)

	err := wmi.Query(query, &processes)
	if err != nil {
		c.logger.Debug("WMI query failed for process", "process", queryName, "error", err)

		// Retry without the .exe suffix.
		if strings.HasSuffix(queryName, ".exe") {
			queryName = strings.TrimSuffix(queryName, ".exe")
			safeQueryName = sanitizeWQLString(queryName)
			query = fmt.Sprintf("SELECT Name, ProcessId, WorkingSetSize, KernelModeTime, UserModeTime FROM Win32_Process WHERE Name = '%s'", safeQueryName)
			err = wmi.Query(query, &processes)
			if err != nil || len(processes) == 0 {
				return nil
			}
		} else {
			return nil
		}
	}

	if len(processes) == 0 {
		c.logger.Debug("process not found via WMI", "process", queryName)
		return nil
	}

	// With several instances running, the first one is reported.
	proc := processes[0]

	// WMI reports CPU time in 100-nanosecond units and memory in bytes.
	cpuTime := time.Duration(proc.KernelModeTime+proc.UserModeTime) * 100 * time.Nanosecond
	memoryMB := float64(proc.WorkingSetSize) / 1048576.0

	c.logger.Debug("process stats retrieved via WMI",
		"process", queryName,
		"pid", proc.ProcessId,
		"cpu_time", cpuTime,
		"memory_mb", memoryMB)

	return &ProcessStats{
		PID:         int(proc.ProcessId),
		CPUTime:     cpuTime,
		MemoryMB:    memoryMB,
		CPUKnown:    true, // WMI returns every field or the query fails
		MemoryKnown: true,
	}
}
