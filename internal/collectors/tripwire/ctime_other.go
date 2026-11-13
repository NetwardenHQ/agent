//go:build !linux && !darwin && !freebsd

package tripwire

import (
	"io/fs"
	"time"
)

// changeTime is the modification time where the platform has no ctime.
func changeTime(info fs.FileInfo) time.Time { return info.ModTime() }
