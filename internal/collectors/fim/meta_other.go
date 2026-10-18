//go:build !linux && !darwin && !freebsd && !windows

package fim

import "os"

// Platforms without a curated FIM port: no owner data, no device check, and a
// plain open. hashFile still verifies the opened descriptor is the regular
// file that was listed.
func fileMeta(_ os.FileInfo) (mode string, uid, gid *uint32) { return "", nil, nil }

func deviceOf(_ os.FileInfo) (uint64, bool) { return 0, false }

func isPseudoFS(_ string) bool { return false }

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
