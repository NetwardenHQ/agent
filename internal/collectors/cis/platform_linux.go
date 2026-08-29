//go:build linux

package cis

// supportedPlatform reports whether CIS evaluation can run here. The probes
// read /proc, /sys and the RHEL package database, none of which exist off
// Linux.
func supportedPlatform() bool { return true }

// newHostProber builds the real host prober.
func newHostProber() Evaluator { return NewLinuxProber() }
