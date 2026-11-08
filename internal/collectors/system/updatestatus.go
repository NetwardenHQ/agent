package system

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// errNotReported means this system keeps no record of what was asked. The
// metric is then left out: the platform shows "not reported", never a guess.
var errNotReported = errors.New("not recorded by this system")

// collectUpdateStatus reports what the OS itself records about its update
// state, next to the counts: whether a reboot is pending, when the update
// catalogue was last checked, and whether a new release is offered. Each is
// cheap to read (a few stats, a registry key), so it is read every cycle and a
// reboot clears the flag at once rather than at the next background check.
func (c *Collector) collectUpdateStatus(ctx context.Context, counts *UpdateCounts, out *[]metrics.Metric) {
	now := time.Now()

	if required, err := c.rebootRequired(ctx); err == nil {
		c.addGauge(out, "system_reboot_required", boolGauge(required))
	} else if !errors.Is(err, errNotReported) {
		c.logger.Debug("reboot-required check failed", "error", err)
	}

	if at, err := c.updatesCheckedAt(counts); err == nil {
		c.addGauge(out, "system_updates_check_age_seconds", max(0, now.Sub(at).Seconds()))
	} else if !errors.Is(err, errNotReported) {
		c.logger.Debug("update check time unavailable", "error", err)
	}

	if available, version, err := c.releaseUpgrade(now); err == nil {
		m, err := c.builder.GaugeWithLabels("system_release_upgrade_available", boolGauge(available),
			map[string]string{"version": version})
		if err == nil {
			*out = append(*out, m)
		}
	} else if !errors.Is(err, errNotReported) {
		c.logger.Debug("release upgrade check failed", "error", err)
	}
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// kernelInstalledSinceBoot reports whether a kernel image other than the
// running one was written after the system booted, which is when a reboot is
// needed to run it. pattern matches the kernel images (/boot/vmlinuz* on
// Linux, /boot/kernel/kernel on FreeBSD); running is the base name of the
// running kernel's image, skipped so that reinstalling it does not count.
//
// It uses the inode change time, not the modification time: dpkg and rpm
// give installed files the modification time recorded in the package, which
// is when it was built, not when it was installed.
func kernelInstalledSinceBoot(pattern, running string, boot time.Time) (bool, error) {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return false, err
	}
	found := false
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		found = true
		if filepath.Base(p) == running {
			continue
		}
		changed, ok := changeTime(fi)
		if !ok {
			return false, errNotReported
		}
		if changed.After(boot) {
			return true, nil
		}
	}
	if !found {
		return false, errNotReported
	}
	return false, nil
}

// aptCheckedAt returns when apt last refreshed its package lists
// successfully: the newest change time of the Release files in dir
// (/var/lib/apt/lists). apt replaces or re-stamps them on every successful
// `apt update`, even when nothing changed, and leaves them alone when the
// refresh fails. (lists/partial is touched by failed refreshes too, and
// periodic/update-success-stamp is only kept by Ubuntu's update-notifier.)
func aptCheckedAt(dir string) (time.Time, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*Release"))
	if err != nil {
		return time.Time{}, err
	}
	var newest time.Time
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if changed, ok := changeTime(fi); ok && changed.After(newest) {
			newest = changed
		}
	}
	if newest.IsZero() {
		return time.Time{}, errNotReported
	}
	return newest, nil
}

// releaseStampMaxAge is how old Ubuntu's release-upgrade answer may be.
// update-motd refreshes it when it is more than a week old, but only while
// building a login message, so a server nobody logs into keeps an old one.
const releaseStampMaxAge = 8 * 24 * time.Hour

var newReleaseLine = regexp.MustCompile(`New release '([^']+)' available`)

// ubuntuReleaseUpgrade reads the answer check-new-release left for the login
// message (/var/lib/ubuntu-release-upgrader/release-upgrade-available): empty
// when no new release is offered, "New release 'X' available." when one is.
func ubuntuReleaseUpgrade(path string, now time.Time) (bool, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, "", errNotReported
	}
	if err != nil {
		return false, "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, "", err
	}
	if now.Sub(fi.ModTime()) > releaseStampMaxAge {
		return false, "", errNotReported
	}
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return false, "", err
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return false, "", nil
	}
	m := newReleaseLine.FindStringSubmatch(text)
	if m == nil {
		return false, "", fmt.Errorf("unrecognised release-upgrade message %q", firstLine(text))
	}
	return true, m[1], nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
