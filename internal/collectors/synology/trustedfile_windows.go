package synology

import (
	"errors"
	"os"
)

// readTrustedFile is only used on DSM (Linux).
func readTrustedFile(string, uint32, int64) ([]byte, os.FileInfo, error) {
	return nil, nil, errors.New("not supported on windows")
}
