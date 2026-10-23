//go:build darwin

package selfupdate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// launchdDaemon is the plist install.sh writes. It runs the agent as root
// with KeepAlive, so an agent that exits is started again.
const launchdDaemon = "/Library/LaunchDaemons/com.netwarden.agent.plist"

func platformSupport() Support {
	if _, err := os.Stat(launchdDaemon); err != nil {
		return Support{Reason: "not running as the com.netwarden.agent launchd daemon"}
	}
	return Support{Available: true, Download: true}
}

// releaseArtifact names the tarball this Mac needs, as the release manifest
// does.
func releaseArtifact() (platform, format, arch string, err error) {
	switch runtime.GOARCH {
	case "amd64":
		return "macos", "tarball", "intel", nil
	case "arm64":
		return "macos", "tarball", "arm64", nil
	}
	return "", "", "", fmt.Errorf("no macOS release is published for %s", runtime.GOARCH)
}

// applyUpdate replaces the agent binary with the verified release and
// restarts. The new binary is staged next to the old one, so the rename that
// swaps them is atomic.
func applyUpdate(ctx context.Context, target Target, signers []string, logger *slog.Logger) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate agent binary: %w", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return fmt.Errorf("locate agent binary: %w", err)
	}

	dir, err := os.MkdirTemp(filepath.Dir(exe), ".netwarden-update-")
	if err != nil {
		return fmt.Errorf("staging directory: %w", err)
	}
	defer os.RemoveAll(dir)

	archive := filepath.Join(dir, "release.tar.gz")
	if err := fetchVerified(ctx, target, archive, signers, logger); err != nil {
		return err
	}
	staged := filepath.Join(dir, "netwarden")
	if err := extractBinary(archive, "netwarden", staged); err != nil {
		return err
	}
	if err := os.Rename(staged, exe); err != nil {
		return fmt.Errorf("replace agent binary: %w", err)
	}

	logger.Info("agent binary replaced, restarting", "version", target.Version)
	if err := restartSelf(); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	return awaitReplacement(ctx, target, 2*time.Minute, "launchctl print system/com.netwarden.agent")
}
