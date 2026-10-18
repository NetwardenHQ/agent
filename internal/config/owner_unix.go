//go:build !windows

package config

import (
	"os"
	"syscall"
)

// fileOwner returns the uid that owns the file described by info.
func fileOwner(info os.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
