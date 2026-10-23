//go:build darwin || freebsd

package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// maxReleaseBytes caps a download. Release packages are tens of MB; a reply
// far larger comes from a malfunctioning or hostile host.
const maxReleaseBytes = 256 << 20

// fetchVerified downloads the release to dst and verifies it before anything
// uses it: against the digest from the API, when there is one, and against
// the release signature, which covers the digest of the bytes actually
// downloaded together with the version and the artifact this host expects.
// dst must be in a directory only root can write.
func fetchVerified(ctx context.Context, target Target, dst string, signers []string, logger *slog.Logger) error {
	platform, format, arch, err := releaseArtifact()
	if err != nil {
		return err
	}

	logger.Info("downloading agent release", "url", target.URL)
	if err := downloadTo(ctx, target.URL, dst); err != nil {
		return err
	}
	digest, err := fileSHA256(dst)
	if err != nil {
		return err
	}
	if target.SHA256 != "" && !strings.EqualFold(digest, target.SHA256) {
		return fmt.Errorf("release digest mismatch: got %s, expected %s", digest, target.SHA256)
	}

	statement := releaseStatement(target.Version, platform, format, arch, digest)
	if err := verifyReleaseSignature(statement, target.Signature, target.Certificate, signers); err != nil {
		return fmt.Errorf("release signature rejected: %w", err)
	}
	logger.Info("agent release verified", "version", target.Version, "artifact", platform+"/"+format+"/"+arch)
	return nil
}

func downloadTo(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: status %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create release file: %w", err)
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxReleaseBytes))
	if err != nil {
		return fmt.Errorf("write release file: %w", err)
	}
	if n == maxReleaseBytes {
		return fmt.Errorf("release exceeded %d bytes", maxReleaseBytes)
	}
	return f.Sync()
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open release file: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash release file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
