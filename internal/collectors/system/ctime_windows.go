//go:build windows

package system

import (
	"os"
	"time"
)

// changeTime: NTFS has no inode change time the agent relies on.
func changeTime(os.FileInfo) (time.Time, bool) { return time.Time{}, false }
