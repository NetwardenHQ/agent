//go:build windows

package spool

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/NetwardenHQ/agent/internal/winsec"
)

// checkTrusted is the Windows form of "root-owned, not group/world
// writable": owned by SYSTEM or Administrators, and no DACL entry lets
// anyone else write, delete, or change permissions. It reads the security
// descriptor through f, so the object checked is the object read.
//
// A directory under ProgramData fails this until it is locked down, because
// ProgramData lets every user create files in its subfolders. EnsureDirs
// creates the spool that way; a pre-existing one can be fixed with
//
//	icacls <dir> /inheritance:r /grant:r SYSTEM:(OI)(CI)F Administrators:(OI)(CI)F
func checkTrusted(f *os.File, _ os.FileInfo, _ int) error {
	return winsec.CheckHandle(windows.Handle(f.Fd()))
}

// checkParents is a no-op on Windows: only the spool directory's own
// descriptor is checked. Whoever controls a parent can replace the spool
// (DELETE on it, or FILE_DELETE_CHILD on the parent), so keep the spool
// under a directory only administrators control. EnsureDirs creates the
// parents that way when they are missing.
func checkParents(string, int) error { return nil }

// mkdirPrivate creates d, and every missing parent, with a protected
// SYSTEM+Administrators DACL. Parents get the same descriptor so a later
// check of a shared parent (such as %ProgramData%\Netwarden, which the
// self-updater also uses) does not find it inheriting ProgramData's
// users-may-create ACL.
func mkdirPrivate(d string) error {
	var missing []string
	for p := d; ; p = filepath.Dir(p) {
		if _, err := os.Lstat(p); err == nil {
			break
		}
		missing = append(missing, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := winsec.MkdirProtected(missing[i]); err != nil {
			return err
		}
	}
	return nil
}

// CanCreateDirs is true: the agent runs as the SYSTEM service, and if it
// does not, creation fails cleanly and the spool is reported as untrusted.
func CanCreateDirs() bool { return true }

const rootUID = 0
