//go:build windows

package opnsense

import "errors"

// processAlive is not supported on Windows. OPNsense is FreeBSD-based, so the
// collector is never enabled there.
func processAlive(int) (bool, error) { return false, errors.New("not supported on windows") }
