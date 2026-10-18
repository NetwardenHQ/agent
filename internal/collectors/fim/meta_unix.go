//go:build linux || darwin || freebsd

package fim

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// fileMeta returns the POSIX mode and uid/gid of a file. FIM tracks these
// because a changed owner on a system binary, or a loosened group on a
// credential file, is an attack whose content bytes may be untouched.
func fileMeta(info os.FileInfo) (mode string, uid, gid *uint32) {
	mode = fmt.Sprintf("%04o", info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return mode, ptr(st.Uid), ptr(st.Gid)
	}
	return mode, nil, nil
}

// deviceOf returns the device a path lives on, so the walk can stay on its
// root's filesystem instead of wandering into a separate mount.
func deviceOf(info os.FileInfo) (uint64, bool) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), true // int32 on darwin, uint64 elsewhere
	}
	return 0, false
}

// isPseudoFS reports kernel pseudo-filesystems. Their "files" are live kernel
// state, not content to baseline, and some block or never end when read.
func isPseudoFS(path string) bool {
	for _, p := range []string{"/proc", "/sys", "/dev"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// openNoFollow opens path for reading without following a final symlink
// (O_NOFOLLOW) and without blocking if it has become a FIFO (O_NONBLOCK).
// os.OpenFile adds O_CLOEXEC itself. O_NONBLOCK has no effect on reads from a
// regular file, which is all hashFile goes on to accept.
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		// A symlink at the final component: ELOOP on Linux and macOS,
		// EMLINK on FreeBSD.
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, errNotRegular
		}
		return nil, err
	}
	return f, nil
}
