//go:build !windows

package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkTrusted refuses anything a non-owner could have planted or altered:
// wrong owner, or writable by group or others. fi comes from fstat on f.
func checkTrusted(_ *os.File, fi os.FileInfo, wantUID int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner")
	}
	if int(st.Uid) != wantUID {
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, wantUID)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("group/world writable (%#o)", fi.Mode().Perm())
	}
	return nil
}

// checkParents verifies every directory from dir up to / (dir already has
// its symlinks resolved). Whoever can write a parent can rename the spool
// away and put their own in its place, so each must be owned by root or the
// spool owner and not group/world writable. A sticky, root-owned directory
// such as /tmp is accepted, since others cannot rename what they do not own.
func checkParents(dir string, wantUID int) error {
	for {
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot determine owner", dir)
		}
		if st.Uid != 0 && int(st.Uid) != wantUID {
			return fmt.Errorf("%s is owned by uid %d", dir, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 && !(fi.Mode()&os.ModeSticky != 0 && st.Uid == 0) {
			return fmt.Errorf("%s is group/world writable (%#o)", dir, fi.Mode().Perm())
		}
		up := filepath.Dir(dir)
		if up == dir {
			return nil
		}
		dir = up
	}
}

// mkdirPrivate creates d (and missing parents) with mode 0700.
func mkdirPrivate(d string) error {
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	return os.Chmod(d, 0o700) // defeat a restrictive umask
}

// CanCreateDirs reports whether EnsureDirs would produce directories the
// trust checks accept: only root creates root-owned ones.
func CanCreateDirs() bool { return os.Geteuid() == 0 }

// rootUID is the owner the spool must have.
const rootUID = 0
