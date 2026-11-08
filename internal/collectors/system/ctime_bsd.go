//go:build freebsd || darwin

package system

import (
	"os"
	"syscall"
	"time"
)

// changeTime returns the inode change time of fi.
func changeTime(fi os.FileInfo) (time.Time, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(st.Ctimespec.Unix()), true
}
