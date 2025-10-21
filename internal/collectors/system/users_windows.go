//go:build windows
// +build windows

package system

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// getWindowsUserCount gets the count of logged-in users on Windows
// Uses 'query user' command which is safe and built-in to Windows
func getWindowsUserCount(ctx context.Context) (int, error) {
	// Create a context with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use 'query user' command to get logged-in users
	// This is a safe, built-in Windows command
	cmd := exec.CommandContext(cmdCtx, "query", "user")
	output, err := cmd.Output()
	if err != nil {
		// If command fails, it might mean no users are logged in
		// or the command is not available (e.g., on Windows Home)
		return 0, nil
	}

	// Parse the output
	// The output has a header line, then one line per user
	lines := strings.Split(string(output), "\n")
	userCount := 0

	for i, line := range lines {
		// Skip header line (first line)
		if i == 0 {
			continue
		}
		// Skip empty lines
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Count valid user lines
		userCount++
	}

	return userCount, nil
}

// getWindowsProcessCount gets the count of running processes on Windows
// Uses WMI via PowerShell which is safe and built-in
func getWindowsProcessCount(ctx context.Context) (int, error) {
	// Create a context with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use PowerShell to count processes via WMI
	// This is safe and doesn't expose process details
	cmd := exec.CommandContext(cmdCtx, "powershell", "-Command", "(Get-Process).Count")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	// Parse the output
	countStr := strings.TrimSpace(string(output))
	count := 0

	// Simple parsing - convert string to int
	for _, char := range countStr {
		if char >= '0' && char <= '9' {
			count = count*10 + int(char-'0')
		}
	}

	return count, nil
}

// getUnixUserCount is not used on Windows systems
func getUnixUserCount(ctx context.Context) (int, error) {
	// This function is only for Unix/Linux
	// Use getWindowsUserCount instead
	return getWindowsUserCount(ctx)
}

// getUnixProcessCount is not used on Windows systems
func getUnixProcessCount(ctx context.Context) (int, error) {
	// This function is only for Unix/Linux
	// Use getWindowsProcessCount instead
	return getWindowsProcessCount(ctx)
}
