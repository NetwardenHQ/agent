//go:build windows

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
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/NetwardenHQ/agent/internal/winsec"
)

// maxInstallerBytes caps the download. Release installers are a few MB; a
// reply far larger than that comes from a malfunctioning or hostile host.
const maxInstallerBytes = 128 * 1024 * 1024

// applyUpdate downloads the signed installer, verifies it, and runs it.
//
// The installer itself performs the upgrade: it stops the netwarden service,
// replaces the executable and recreates the service. The agent therefore
// never overwrites the binary it is executing, and the upgrade takes the same
// path as a manual one, including preserving netwarden.conf.
//
// Every check runs against one pinned object. The file is downloaded into a
// directory only SYSTEM and Administrators can write (not %TEMP%, which for
// SYSTEM is C:\Windows\Temp, where other accounts can create files), then
// reopened with read-only sharing: from the digest check until the installer
// has exited, nobody can open it for writing, rename it or delete it, so the
// bytes that run are the bytes that were verified.
func applyUpdate(ctx context.Context, target Target, signers []string, logger *slog.Logger) error {
	dir, err := updateDir()
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	installer := filepath.Join(dir, "netwarden-installer.exe")
	if err := download(ctx, target.URL, installer, logger); err != nil {
		return err
	}

	f, err := openPinned(installer)
	if err != nil {
		return err
	}
	defer f.Close() // runs before RemoveAll: deferred later

	// Digest first, when the API supplied one. It comes from a different
	// place than the file, so a compromised download host alone cannot swap
	// the bytes. A locally mirrored URL has no vendor digest to check
	// against; the signature below still applies.
	if target.SHA256 != "" {
		if err := verifySHA256(f, target.SHA256); err != nil {
			return err
		}
		logger.Info("installer digest verified", "version", target.Version)
	}

	// The security boundary. Until here the file is untrusted bytes from the
	// network. Nothing runs until Windows confirms the file is signed, the
	// chain is trusted, and the signer is pinned.
	if err := verifyAuthenticode(windows.Handle(f.Fd()), installer, signers); err != nil {
		return fmt.Errorf("installer signature rejected: %w", err)
	}
	logger.Info("installer signature verified", "version", target.Version)

	// The offered version was only a claim. The one embedded in the signed
	// installer is not, and it must match the offer and be an upgrade, or an
	// old genuine installer paired with a big version number would downgrade
	// the host.
	embedded, err := installerVersion(installer)
	if err != nil {
		return err
	}
	if err := checkInstallerVersion(embedded, target.Version, target.Current); err != nil {
		return fmt.Errorf("installer refused: %w", err)
	}

	// /S is NSIS silent mode. The installer detects the existing
	// netwarden.conf and keeps the configured credentials.
	cmd := exec.CommandContext(ctx, installer, "/S")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("installer failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// The installer restarts the service, which replaces this process. If
	// this process is still running 30 seconds later, the upgrade did not
	// take effect and must be reported as a failure.
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return ctx.Err()
	}
	return fmt.Errorf("installer for %s exited cleanly but the service was not restarted; still running %s",
		target.Version, target.Current)
}

// updateDir creates a fresh per-attempt directory under
// %ProgramData%\Netwarden\updates. Both levels are created with a protected
// SYSTEM+Administrators DACL; if either already exists it must already be
// that tight, because ProgramData lets any user pre-create folders in it.
func updateDir() (string, error) {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", fmt.Errorf("locate ProgramData: %w", err)
	}
	base := filepath.Join(pd, "Netwarden")
	updates := filepath.Join(base, "updates")
	for _, d := range []string{base, updates} {
		if err := winsec.MkdirProtected(d); err != nil {
			return "", fmt.Errorf("update directory: %w", err)
		}
	}
	dir, err := os.MkdirTemp(updates, "update-")
	if err != nil {
		return "", fmt.Errorf("update directory: %w", err)
	}
	return dir, nil
}

// openPinned opens the installer for reading and denies everyone else write
// and delete access (no FILE_SHARE_WRITE, no FILE_SHARE_DELETE) for as long
// as the handle is open. Reading and executing it stay possible.
func openPinned(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("pin installer: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("pin installer: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("installer path is not a plain file")
	}
	if err := winsec.CheckHandle(h); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("installer file is not protected: %w", err)
	}
	return os.NewFile(uintptr(h), path), nil
}

func download(ctx context.Context, url, dst string, logger *slog.Logger) error {
	logger.Info("downloading agent installer", "url", url)

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
		return fmt.Errorf("create installer file: %w", err)
	}
	defer f.Close()

	n, err := io.Copy(f, io.LimitReader(resp.Body, maxInstallerBytes))
	if err != nil {
		return fmt.Errorf("write installer: %w", err)
	}
	if n == maxInstallerBytes {
		return fmt.Errorf("installer exceeded %d bytes", maxInstallerBytes)
	}
	return f.Sync()
}

// verifySHA256 checks the pinned file against the digest the API supplied.
func verifySHA256(r io.Reader, want string) error {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("hash installer: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("installer digest mismatch: got %s, expected %s", got, want)
	}
	return nil
}

// installerVersion reads the FileVersion string from the installer's
// VERSIONINFO resource. The release script sets it to the exact release
// version (VIAddVersionKey "FileVersion" in the NSIS script); the numeric
// VS_FIXEDFILEINFO cannot hold a pre-release tag, so the string is the one
// that can be compared with the offer. The resource sits inside the signed
// image, so once the signature is verified this value is trusted.
func installerVersion(path string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return "", fmt.Errorf("installer has no version resource: %v", err)
	}
	buf := make([]byte, size)
	block := unsafe.Pointer(&buf[0])
	if err := windows.GetFileVersionInfo(path, 0, size, block); err != nil {
		return "", fmt.Errorf("read installer version resource: %w", err)
	}

	var trans unsafe.Pointer
	var transLen uint32
	if err := windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&trans), &transLen); err != nil || transLen < 4 {
		return "", fmt.Errorf("installer version resource has no translation table")
	}
	for _, lc := range unsafe.Slice((*[2]uint16)(trans), transLen/4) {
		sub := fmt.Sprintf(`\StringFileInfo\%04x%04x\FileVersion`, lc[0], lc[1])
		var val unsafe.Pointer
		var n uint32 // characters, including the terminating NUL
		if err := windows.VerQueryValue(block, sub, unsafe.Pointer(&val), &n); err != nil || n == 0 {
			continue
		}
		if v := windows.UTF16ToString(unsafe.Slice((*uint16)(val), n)); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("installer version resource has no FileVersion")
}
