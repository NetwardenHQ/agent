//go:build windows

package config

import "os"

// fileOwner is unavailable on Windows, where ownership lives in the ACL.
func fileOwner(os.FileInfo) (int, bool) { return 0, false }
