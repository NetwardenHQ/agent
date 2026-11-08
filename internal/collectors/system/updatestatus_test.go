//go:build linux || freebsd || darwin

package system

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKernelInstalledAfterBootNeedsReboot(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "vmlinuz-6.8.0-45-generic"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "vmlinuz-6.8.0-49-generic"), nil, 0o600)
	os.Symlink("vmlinuz-6.8.0-49-generic", filepath.Join(dir, "vmlinuz"))
	pattern := filepath.Join(dir, "vmlinuz*")

	bootedBefore := time.Now().Add(-time.Hour)
	if got, err := kernelInstalledSinceBoot(pattern, "vmlinuz-6.8.0-45-generic", bootedBefore); err != nil || !got {
		t.Fatalf("a kernel written after boot that is not the running one: got %v, %v; want true", got, err)
	}
	// Booted after both were written: the running kernel is whatever was chosen.
	bootedAfter := time.Now().Add(time.Hour)
	if got, err := kernelInstalledSinceBoot(pattern, "vmlinuz-6.8.0-45-generic", bootedAfter); err != nil || got {
		t.Fatalf("kernels written before boot: got %v, %v; want false", got, err)
	}
	// Only the running kernel was rewritten (a reinstall): no reboot for that.
	only := filepath.Join(dir, "vmlinuz-6.8.0-45-generic")
	if got, err := kernelInstalledSinceBoot(only, "vmlinuz-6.8.0-45-generic", bootedBefore); err != nil || got {
		t.Fatalf("the running kernel itself: got %v, %v; want false", got, err)
	}
}

func TestKernelCheckWithoutImagesIsNotReported(t *testing.T) {
	// A container or a UKI system has no kernel image to compare; that is
	// "unknown", never "no reboot needed".
	dir := t.TempDir()
	os.Symlink("/nonexistent", filepath.Join(dir, "vmlinuz"))
	_, err := kernelInstalledSinceBoot(filepath.Join(dir, "vmlinuz*"), "x", time.Now())
	if !errors.Is(err, errNotReported) {
		t.Fatalf("got %v, want errNotReported", err)
	}
}

func TestAptCheckedAtIsTheNewestReleaseFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := aptCheckedAt(dir); !errors.Is(err, errNotReported) {
		t.Fatalf("no lists: got %v, want errNotReported", err)
	}
	os.WriteFile(filepath.Join(dir, "archive.ubuntu.com_ubuntu_dists_resolute_InRelease"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "archive.ubuntu.com_ubuntu_dists_resolute_main_binary-amd64_Packages"), nil, 0o644)
	at, err := aptCheckedAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(at); d < 0 || d > time.Minute {
		t.Fatalf("checked at %v, want about now", at)
	}
}

func TestUbuntuReleaseUpgrade(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "release-upgrade-available")
	now := time.Now()

	if _, _, err := ubuntuReleaseUpgrade(p, now); !errors.Is(err, errNotReported) {
		t.Fatalf("missing file: got %v, want errNotReported", err)
	}

	os.WriteFile(p, []byte("\nNew release '26.04.1 LTS' available.\nRun 'do-release-upgrade' to upgrade to it.\n\n"), 0o644)
	if ok, ver, err := ubuntuReleaseUpgrade(p, now); err != nil || !ok || ver != "26.04.1 LTS" {
		t.Fatalf("got %v %q %v; want true \"26.04.1 LTS\"", ok, ver, err)
	}

	// check-new-release found nothing: it leaves the file empty.
	os.WriteFile(p, nil, 0o644)
	if ok, _, err := ubuntuReleaseUpgrade(p, now); err != nil || ok {
		t.Fatalf("empty file: got %v %v; want false", ok, err)
	}

	// The file is only refreshed when the login message is built. An old
	// answer is not today's answer.
	old := now.Add(-9 * 24 * time.Hour)
	os.Chtimes(p, old, old)
	if _, _, err := ubuntuReleaseUpgrade(p, now); !errors.Is(err, errNotReported) {
		t.Fatalf("stale file: got %v, want errNotReported", err)
	}

	os.WriteFile(p, []byte("Neue Version '26.04' verfügbar.\n"), 0o644)
	if _, _, err := ubuntuReleaseUpgrade(p, now); err == nil {
		t.Fatal("text that is not the expected message must be an error, not 'available'")
	}
}
