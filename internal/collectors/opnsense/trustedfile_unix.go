//go:build !windows

package opnsense

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// readTrustedFile reads a small file that sits in a world-writable directory
// (OPNsense's update check writes /tmp/pkg_upgrade.json). It refuses
// symlinks, FIFOs and anything else that is not a regular file owned by
// owner and not writable by group or others, and reads at most max bytes, so
// a local user cannot make the root agent block, read another file, or
// believe a planted status.
func readTrustedFile(path string, owner uint32, max int64) ([]byte, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.Mode().IsRegular():
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	case !ok || sys.Uid != owner:
		return nil, nil, fmt.Errorf("%s is not owned by uid %d", path, owner)
	case st.Mode().Perm()&0o022 != 0:
		return nil, nil, fmt.Errorf("%s is writable by group or others", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > max {
		return nil, nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return data, st, nil
}
