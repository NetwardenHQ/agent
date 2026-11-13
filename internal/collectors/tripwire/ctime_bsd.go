//go:build darwin || freebsd

package tripwire

import (
	"io/fs"
	"syscall"
	"time"
)

// changeTime is when the file's content or name last changed (ctime), so a
// rename counts as a change.
func changeTime(info fs.FileInfo) time.Time {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(st.Ctimespec.Sec), int64(st.Ctimespec.Nsec))
	}
	return info.ModTime()
}
