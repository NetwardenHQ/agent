//go:build !linux && !darwin && !freebsd && !windows

package fim

import (
	"fmt"
	"os"
)

// checkTrust on platforms without a curated FIM port checks only that the
// manifest is not group/world-writable; ownership is not inspected.
func checkTrust(path string, f *os.File) (bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("%w: %v", errManifestUntrusted, err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return false, fmt.Errorf("%w: %s is group- or world-writable", errManifestUntrusted, path)
	}
	return fi.Mode().Perm()&insecureModeMask != 0, nil
}

func ensureStateDir(dir string) error { return os.MkdirAll(dir, 0o700) }

func protectFile(string) error { return nil }
