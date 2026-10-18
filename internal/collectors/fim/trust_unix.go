//go:build linux || darwin || freebsd

package fim

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// writableByOthers matches the group and world write bits.
const writableByOthers = 0o022

// checkTrust decides whether a manifest can be relied on. Both the file and
// its directory must be owned by root or by the agent's own user (so an
// unprivileged install still works) and must not be group/world-writable: a
// writable directory lets another account replace the file outright.
// Group/world-readable is reported as insecure but still trusted.
func checkTrust(path string, f *os.File) (bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("%w: %v", errManifestUntrusted, err)
	}
	if err := trustedOwnerAndMode(path, fi); err != nil {
		return false, err
	}
	dir := filepath.Dir(path)
	di, err := os.Stat(dir)
	if err != nil {
		return false, fmt.Errorf("%w: %v", errManifestUntrusted, err)
	}
	if err := trustedOwnerAndMode(dir, di); err != nil {
		return false, err
	}
	return fi.Mode().Perm()&insecureModeMask != 0, nil
}

func trustedOwnerAndMode(path string, fi os.FileInfo) error {
	if fi.Mode().Perm()&writableByOthers != 0 {
		return fmt.Errorf("%w: %s is group- or world-writable (%04o)", errManifestUntrusted, path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if euid := uint32(os.Geteuid()); st.Uid != 0 && st.Uid != euid {
			return fmt.Errorf("%w: %s is owned by uid %d", errManifestUntrusted, path, st.Uid)
		}
	}
	return nil
}

// ensureStateDir creates the manifest directory owner-only. An existing
// directory is left as it is (it may be shared agent state); checkTrust
// refuses it on load if it is unsafe.
func ensureStateDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// protectFile is a no-op on Unix: the temp manifest is already chmod 0600.
func protectFile(string) error { return nil }
