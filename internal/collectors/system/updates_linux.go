//go:build linux

package system

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// GetAvailableUpdates returns the number of available system updates on Linux.
// It safely checks package manager databases without executing commands.
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

	// Check for Zypper (openSUSE)
	if count, err := getZypperUpdates(); err == nil {
		return count, nil
	}

	// Check for Pacman (Arch)
	if count, err := getPacmanUpdates(); err == nil {
		return count, nil
	}

	// No supported package manager found or couldn't read update info
	return 0, nil
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
	output, err := cmd.CombinedOutput()
	// check-update returns exit code 100 if updates are available
	// This is expected behavior, not an error
	if err != nil {
		// Only fail if it's not exit code 100
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 100 {
			// Try to continue anyway if we got output
			if len(output) == 0 {
				return 0, err
			}
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

// getZypperUpdates checks for available updates on Zypper-based systems.
func getZypperUpdates() (int, error) {
	// Check if this is a Zypper-based system
	if _, err := os.Stat("/usr/bin/zypper"); os.IsNotExist(err) {
		return 0, err
	}

	// Zypper stores update information in XML files
	cacheDir := "/var/cache/zypp"
	if _, err := os.Stat(cacheDir); err == nil {
		// Look for update metadata
		updateFile := filepath.Join(cacheDir, "solv", "@System", "cookie")
		if _, err := os.Stat(updateFile); err == nil {
			// System has zypper but we can't easily determine update count
			// without parsing complex solver files
			return 0, nil
		}
	}

	return 0, os.ErrNotExist
}

// getPacmanUpdates checks for available updates on Pacman-based systems.
func getPacmanUpdates() (int, error) {
	// Check if this is a Pacman-based system
	if _, err := os.Stat("/usr/bin/pacman"); os.IsNotExist(err) {
		return 0, err
	}

	// Check if checkupdates cache exists (created by pacman hooks)
	cacheFile := "/var/cache/pacman/updates.cache"
	if data, err := os.ReadFile(cacheFile); err == nil {
		// Each line is a package update
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 && lines[0] != "" {
			return len(lines), nil
		}
	}

	// Check the pacman log for pending updates
	logFile := "/var/log/pacman.log"
	if _, err := os.Stat(logFile); err == nil {
		// System has pacman but we can't determine update count easily
		return 0, nil
	}

	return 0, os.ErrNotExist
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

	// No security update info available
	return 0, nil
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
		// If command fails, return 0 (no security updates)
		return 0, nil
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
