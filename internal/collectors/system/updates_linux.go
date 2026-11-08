//go:build linux

package system

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
)

// errNoPackageManager: none of the package managers the agent can read is
// installed, so there is no count to report (and zero would be a guess).
var errNoPackageManager = errors.New("no supported package manager (apt, dnf/yum, pacman) found")

// GetAvailableUpdates returns the number of available system updates on Linux.
func (c *Collector) GetAvailableUpdates(ctx context.Context) (int, error) {
	// Try different package managers in order of prevalence

	// Check for APT (Debian/Ubuntu)
	if count, err := getAPTUpdates(); err == nil {
		return count, nil
	}

	// Check for YUM/DNF (RHEL/Fedora/CentOS)
	if count, err := getYumDnfUpdates(); err == nil {
		return count, nil
	}

	// Check for Pacman (Arch)
	if count, err := getPacmanUpdates(); err == nil {
		return count, nil
	}

	return 0, errNoPackageManager
}

// getAPTUpdates checks for available updates on APT-based systems.
func getAPTUpdates() (int, error) {
	// Check if this is an APT-based system
	if _, err := os.Stat("/usr/bin/apt"); os.IsNotExist(err) {
		return 0, err
	}

	// Try apt-check first (fastest and most reliable)
	if _, err := os.Stat("/usr/lib/update-notifier/apt-check"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "/usr/lib/update-notifier/apt-check")
		output, err := cmd.CombinedOutput()
		if err == nil || len(output) > 0 {
			// apt-check returns format: "regular;security" to stderr
			parts := strings.Split(strings.TrimSpace(string(output)), ";")
			if len(parts) >= 1 {
				if count, err := strconv.Atoi(parts[0]); err == nil {
					return count, nil
				}
			}
		}
	}

	// Fallback to apt list --upgradable
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/apt", "list", "--upgradable")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	// Count lines that contain upgradable packages
	// Skip the first line which is "Listing..."
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "[upgradable") {
			count++
		}
	}

	return count, nil
}

// getYumDnfUpdates checks for available updates on YUM/DNF-based systems.
func getYumDnfUpdates() (int, error) {
	// Check if this is a YUM-based system (works on all RedHat variants)
	// On modern systems (RHEL 8+, Fedora 18+), yum is a symlink to dnf
	if _, err := os.Stat("/usr/bin/yum"); os.IsNotExist(err) {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/yum", "check-update", "--quiet", "--assumeyes")
	// Set XDG_STATE_HOME to redirect dnf5 logs to a writable directory
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME=/var/log/netwarden/.dnf-state")
	output, err := cmd.Output()
	// check-update exits 100 when updates are available and 0 when there are
	// none. Anything else is a failure, whatever it printed: counting the
	// lines of an error message would report them as updates.
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 100 {
			return 0, fmt.Errorf("yum check-update: %w", err)
		}
	}

	// Count package lines (skip headers and empty lines)
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()

		// Stop parsing at "Obsoleting packages" section (contains duplicates)
		if strings.HasPrefix(line, "Obsoleting packages") {
			break
		}

		// Skip indented lines (old versions in obsoleting section)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}

		lineTrimmed := strings.TrimSpace(line)
		// Package lines contain package name, version, and repository
		// Format: "package.arch    version    repository"
		if lineTrimmed != "" && !strings.HasPrefix(lineTrimmed, "Last metadata") && !strings.HasPrefix(lineTrimmed, "Security:") {
			parts := strings.Fields(lineTrimmed)
			// Valid package line has at least 3 parts
			if len(parts) >= 3 {
				count++
			}
		}
	}
	return count, nil
}

// getPacmanUpdates checks for available updates on Pacman-based systems.
func getPacmanUpdates() (int, error) {
	// Check if this is a Pacman-based system
	if _, err := os.Stat("/usr/bin/pacman"); os.IsNotExist(err) {
		return 0, err
	}

	// A pacman hook can leave checkupdates' output here, one update a line.
	// Without it there is no count: pacman itself keeps none offline.
	data, err := os.ReadFile("/var/cache/pacman/updates.cache")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n, nil
}

// GetSecurityUpdates returns the number of available security updates on Linux.
func (c *Collector) GetSecurityUpdates(ctx context.Context) (int, error) {
	// Try different package managers in order of prevalence

	// Check for APT (Debian/Ubuntu)
	if count, err := getAPTSecurityUpdates(); err == nil {
		return count, nil
	}

	// Check for YUM/DNF (RHEL/Fedora/CentOS)
	if count, err := getYumDnfSecurityUpdates(); err == nil {
		return count, nil
	}

	return 0, errors.New("no security update information (apt or dnf/yum updateinfo) available")
}

// getAPTSecurityUpdates checks for available security updates on APT-based systems.
func getAPTSecurityUpdates() (int, error) {
	// Check if this is an APT-based system
	if _, err := os.Stat("/usr/bin/apt"); os.IsNotExist(err) {
		return 0, err
	}

	// Try apt-check first (fastest and most reliable)
	if _, err := os.Stat("/usr/lib/update-notifier/apt-check"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "/usr/lib/update-notifier/apt-check")
		output, err := cmd.CombinedOutput()
		if err == nil || len(output) > 0 {
			// apt-check returns format: "regular;security" to stderr
			parts := strings.Split(strings.TrimSpace(string(output)), ";")
			if len(parts) >= 2 {
				if count, err := strconv.Atoi(parts[1]); err == nil {
					return count, nil
				}
			}
		}
	}

	// Fallback to apt list --upgradable and check for security origin
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/apt", "list", "--upgradable")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	// Count lines from security repositories
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "[upgradable") && (strings.Contains(line, "-security") || strings.Contains(line, "security")) {
			count++
		}
	}

	return count, nil
}

// getYumDnfSecurityUpdates checks for available security updates on YUM/DNF-based systems.
func getYumDnfSecurityUpdates() (int, error) {
	// Check if this is a YUM-based system (works on all RedHat variants)
	// On modern systems (RHEL 8+, Fedora 18+), yum is a symlink to dnf
	if _, err := os.Stat("/usr/bin/yum"); os.IsNotExist(err) {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/yum", "updateinfo", "list", "security", "--quiet", "--assumeyes")
	// Set XDG_STATE_HOME to redirect dnf5 logs to a writable directory
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME=/var/log/netwarden/.dnf-state")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("yum updateinfo: %w", err)
	}

	// Count security update lines
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip headers and empty lines
		if line != "" && !strings.HasPrefix(line, "Last metadata") && !strings.HasPrefix(line, "UpdateInfo list done") {
			// Valid security update line
			if strings.Contains(line, "FEDORA") || strings.Contains(line, "RHEL") || strings.Contains(line, "/Sec.") {
				count++
			}
		}
	}

	return count, nil
}

// rebootRequired: Debian and Ubuntu flag a pending reboot in
// /run/reboot-required (any package may ask for one). Beyond that, and on
// every other distribution, a kernel installed since boot needs a reboot.
func (c *Collector) rebootRequired(ctx context.Context) (bool, error) {
	for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		if _, err := os.Stat(p); err == nil {
			return true, nil
		}
	}
	boot, err := host.BootTimeWithContext(ctx)
	if err != nil {
		return false, err
	}
	release, err := host.KernelVersionWithContext(ctx)
	if err != nil {
		return false, err
	}
	return kernelInstalledSinceBoot("/boot/vmlinuz*", "vmlinuz-"+release, time.Unix(int64(boot), 0))
}

// updatesCheckedAt returns when the package catalogue was last checked. apt
// records it in its lists. dnf and yum keep no such record (a failed refresh
// touches the same files as a successful one), but they refresh expired
// metadata themselves during the agent's check-update, so that check's time
// is the answer there.
func (c *Collector) updatesCheckedAt(counts *UpdateCounts) (time.Time, error) {
	if _, err := os.Stat("/usr/bin/apt"); err == nil {
		return aptCheckedAt("/var/lib/apt/lists")
	}
	if _, err := os.Stat("/usr/bin/yum"); err == nil && counts != nil && !counts.CheckedAt.IsZero() {
		return counts.CheckedAt, nil
	}
	return time.Time{}, errNotReported
}

// releaseUpgrade reports a new distribution release. Only Ubuntu records one
// locally; elsewhere it is not reported.
func (c *Collector) releaseUpgrade(now time.Time) (bool, string, error) {
	return ubuntuReleaseUpgrade("/var/lib/ubuntu-release-upgrader/release-upgrade-available", now)
}
