package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxBinaryBytes caps the binary taken out of a release archive.
const maxBinaryBytes = 256 << 20

// extractBinary copies the regular file called name out of a verified
// tar.gz into dst, executable.
func extractBinary(archive, name, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("open release: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("read release: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("release contains no %s", name)
		}
		if err != nil {
			return fmt.Errorf("read release: %w", err)
		}
		if filepath.Clean(hdr.Name) != name || hdr.Typeflag != tar.TypeReg {
			continue
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("stage binary: %w", err)
		}
		n, err := io.Copy(out, io.LimitReader(tr, maxBinaryBytes))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("stage binary: %w", err)
		}
		if n == maxBinaryBytes {
			return fmt.Errorf("binary in release exceeded %d bytes", maxBinaryBytes)
		}
		return nil
	}
}
