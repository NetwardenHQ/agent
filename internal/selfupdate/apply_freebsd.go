//go:build freebsd

package selfupdate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// applyHelper is installed by the netwarden-agent package. It installs a
	// package the agent has verified, checks the installed version and
	// restarts the service.
	applyHelper = "/usr/local/libexec/netwarden/apply-update"

	// updatesDir holds the download until the helper has installed it.
	updatesDir = "/var/db/netwarden/updates"
)

func platformSupport() Support {
	if _, err := os.Stat(applyHelper); err != nil {
		return Support{Reason: "not installed from the netwarden-agent package"}
	}
	return Support{Available: true, Download: true}
}

// releaseArtifact names the package for this host's FreeBSD release, as the
// release manifest does: platform freebsd14 or freebsd15.
func releaseArtifact() (platform, format, arch string, err error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", "", "", fmt.Errorf("read FreeBSD release: %w", err)
	}
	release := unix.ByteSliceToString(u.Release[:])
	major, _, ok := strings.Cut(release, ".")
	if !ok || major == "" {
		return "", "", "", fmt.Errorf("unrecognized FreeBSD release %q", release)
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return "freebsd" + major, "pkg", runtime.GOARCH, nil
	}
	return "", "", "", fmt.Errorf("no FreeBSD package is published for %s", runtime.GOARCH)
}

// applyUpdate downloads and verifies the package, then hands it to the helper
// through daemon(8): restarting the service ends this process, so the
// install must not be its child.
func applyUpdate(ctx context.Context, target Target, signers []string, logger *slog.Logger) error {
	if err := os.MkdirAll(updatesDir, 0o700); err != nil {
		return fmt.Errorf("update directory: %w", err)
	}
	if err := rootOnly(updatesDir); err != nil {
		return err
	}

	pkg := filepath.Join(updatesDir, "netwarden-agent-"+target.Version+".pkg")
	_ = os.Remove(pkg) // left by an earlier attempt that failed
	if err := fetchVerified(ctx, target, pkg, signers, logger); err != nil {
		_ = os.Remove(pkg)
		return err
	}

	out, err := exec.CommandContext(ctx, "/usr/sbin/daemon", "-f", applyHelper, pkg, target.Version).CombinedOutput()
	if err != nil {
		_ = os.Remove(pkg)
		return fmt.Errorf("start %s: %w (%s)", applyHelper, err, strings.TrimSpace(string(out)))
	}
	logger.Info("package install started", "version", target.Version)
	return awaitReplacement(ctx, target, restartGrace, "/var/log/messages (netwarden-update)")
}

// rootOnly refuses a directory another account could write to, or that is a
// symlink: the verified package must still be the verified package when the
// helper installs it.
func rootOnly(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("update directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("update directory %s is not a directory", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("update directory %s is not owned by root", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("update directory %s is writable by others", dir)
	}
	return nil
}
