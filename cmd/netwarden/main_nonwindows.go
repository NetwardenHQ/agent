//go:build !windows
// +build !windows

// Package main provides stub implementations for Windows-specific functions on non-Windows platforms.
package main

import (
	"fmt"
)

// runService is a stub implementation for non-Windows platforms.
// This function should never be called on non-Windows systems.
func runService(configFile string, isDebug bool) error {
	return fmt.Errorf("Windows service mode is not supported on this platform")
}

// checkServiceMode is a stub implementation for non-Windows platforms.
// This function should never be called on non-Windows systems.
func checkServiceMode() (bool, error) {
	return false, nil
}
