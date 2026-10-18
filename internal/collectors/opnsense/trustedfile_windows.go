package opnsense

import (
	"errors"
	"os"
)

// readTrustedFile is only used on OPNsense (FreeBSD).
func readTrustedFile(string, uint32, int64) ([]byte, os.FileInfo, error) {
	return nil, nil, errors.New("not supported on windows")
}
