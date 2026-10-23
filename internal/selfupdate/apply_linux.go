//go:build linux

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const (
	// packageUpdater is installed by the .deb and .rpm packages, together
	// with the netwarden-update.path and netwarden-update.service units
	// that run it as root, outside the agent's sandbox.
	packageUpdater = "/usr/lib/netwarden/update-agent"

	// upgradeRequest is the file netwarden-update.path watches. Its presence
	// is the whole request: the updater installs whatever the signed
	// Netwarden repository holds, never a version read from this file.
	upgradeRequest = "/var/lib/netwarden/update-request"

	serviceAccountToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// platformSupport: the agent's systemd unit sets ProtectSystem=strict, so it
// cannot replace its own binary even as root. Packaged installs upgrade
// through the package manager instead; in Kubernetes a restart pulls the
// image again. A manual install, a container elsewhere and the Synology
// package, which runs as an unprivileged package user, have neither.
func platformSupport() Support {
	if inKubernetes() {
		return Support{Available: true}
	}
	if _, err := os.Stat(packageUpdater); err != nil {
		return Support{Reason: "no package updater on this host (manual install, container or Synology package)"}
	}
	return Support{Available: true}
}

func inKubernetes() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return false
	}
	_, err := os.Stat(serviceAccountToken)
	return err == nil
}

func applyUpdate(ctx context.Context, target Target, _ []string, logger *slog.Logger) error {
	if inKubernetes() {
		// The Deployment Netwarden generates runs the latest tag with
		// imagePullPolicy Always, so the restarted container is the new
		// release. A Deployment pinned to a tag restarts into the same
		// version; set self_update: false there.
		logger.Info("restarting to pick up the new agent image", "version", target.Version)
		if err := restartSelf(); err != nil {
			return fmt.Errorf("restart: %w", err)
		}
		return awaitReplacement(ctx, target, 2*time.Minute, "the Deployment's image tag and pull policy")
	}

	if err := writeUpgradeRequest(upgradeRequest, target.Version); err != nil {
		return err
	}
	logger.Info("package upgrade requested", "version", target.Version)
	// The package's postinst restarts the netwarden service, which ends
	// this process.
	return awaitReplacement(ctx, target, restartGrace, "journalctl -u netwarden-update")
}

// writeUpgradeRequest creates the request atomically, so the path unit never
// fires on a half-written file.
func writeUpgradeRequest(path, version string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".update-request-")
	if err != nil {
		return fmt.Errorf("write upgrade request: %w", err)
	}
	name := f.Name()
	_, werr := f.WriteString(version + "\n")
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(name)
		return fmt.Errorf("write upgrade request: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("write upgrade request: %w", err)
	}
	return nil
}
