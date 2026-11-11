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

// attemptsFile is in /tmp because the Deployment Netwarden generates mounts
// an emptyDir there: it outlives the container restart that an update is,
// and is gone with the pod.
func attemptsFile() string {
	if inKubernetes() {
		return "/tmp/netwarden-update-attempts.json"
	}
	return ""
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
		return applyInKubernetes(ctx, target, logger)
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

// applyInKubernetes asks Kubernetes for a new pod, which pulls the new image:
// the same as `kubectl rollout restart` on the agent's Deployment, so the pod
// is replaced rather than its container restarted in place, and its restart
// count stays a count of failures.
//
// An install from before the agent was allowed to restart its Deployment
// gets the container restart it always had: the kubelet starts it again and
// pulls the image. The attempt is recorded in attemptsFile first, so a
// Deployment pinned to another tag reports self-update as unsupported for a
// day instead of restarting every night.
func applyInKubernetes(ctx context.Context, target Target, logger *slog.Logger) error {
	api, err := inClusterAPI()
	if err == nil {
		err = api.replacePod(ctx, target.Version, time.Now())
		if err == nil {
			logger.Info("asked Kubernetes to replace this pod with the new agent image", "version", target.Version)
			return awaitReplacement(ctx, target, 5*time.Minute, "kubectl rollout status deployment/netwarden-agent")
		}
		if errors.Is(err, errWouldNotUpdate) {
			return err
		}
	}
	logger.Info("restarting to pick up the new agent image", "version", target.Version, "why_not_a_new_pod", err)
	if err := restartSelf(); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	return awaitReplacement(ctx, target, 2*time.Minute, "the Deployment's image tag and pull policy")
}
