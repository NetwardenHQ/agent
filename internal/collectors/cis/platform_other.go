//go:build !linux

package cis

import (
	"context"
	"errors"
)

// supportedPlatform reports false off Linux. The CIS RHEL benchmark's probes
// (/proc/sys, /proc/modules, modprobe.d, rpm, SELinux) have no meaningful
// equivalent on macOS or Windows, and a partially-evaluated benchmark is
// worse than none: it produces a compliance score that looks authoritative
// and is not.
func supportedPlatform() bool { return false }

// unsupportedProber fails every probe. Never reached in practice, since
// Enabled() is false off Linux, but keeps the package buildable everywhere so
// cross-compilation and the shared registration path stay simple.
type unsupportedProber struct{}

func (unsupportedProber) Observe(context.Context, Probe) (string, error) {
	return "", errors.New("CIS evaluation is not supported on this platform")
}

func newHostProber() Evaluator { return unsupportedProber{} }

// isNotApplicable has a Linux implementation alongside notApplicableError;
// off Linux nothing produces that error.
func isNotApplicable(error) bool { return false }
