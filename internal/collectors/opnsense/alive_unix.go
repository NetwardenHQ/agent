//go:build !windows

package opnsense

import "syscall"

// processAlive reports whether a process exists, using signal 0.
func processAlive(pid int) (bool, error) {
	err := syscall.Kill(pid, 0)
	switch err {
	case nil, syscall.EPERM: // EPERM: it exists but may not be signaled
		return true, nil
	case syscall.ESRCH:
		return false, nil
	}
	return false, err
}
