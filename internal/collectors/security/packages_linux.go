//go:build linux

package security

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"netwarden/internal/metrics"
)

// Enabled returns true on Linux. The Collect path itself decides whether the
// distro is supported and emits a single warning if not.
func (c *PackagesCollector) Enabled() bool {
	return true
}

// Collect lists installed packages with versions for downstream CVE matching.
//
// Output is one snapshot metric (`security_installed_package_snapshot`,
// value = total count, label `snapshot` = JSON array) plus the count gauge
// and the distro identifier metric. Even an 800-package server only sends
// O(few) metrics — never one-per-package — so the upload payload stays bounded.
func (c *PackagesCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	timestamp := time.Now()

	// Throttle: re-enumerating dpkg/rpm and re-shipping the inventory every
	// reporting interval is pure waste. On intervening cycles re-emit the
	// cached gauges under a fresh timestamp so the series stays continuous,
	// and return no snapshot.
	due, cached := c.shouldCollect(timestamp)
	if !due {
		c.logger.Debug("installed packages: throttled, re-emitting cached metrics")
		refreshed := make([]metrics.Metric, 0, len(cached))
		for _, m := range cached {
			m.Timestamp = timestamp
			refreshed = append(refreshed, m)
		}
		return refreshed, nil
	}

	c.logger.Debug("collecting installed packages")
	c.builder = c.builder.WithTimestamp(timestamp)

	distro, err := readOSRelease("/etc/os-release")
	if err != nil {
		c.logger.Warn("failed to read /etc/os-release", "error", err)
		// Continue: emit zero-count snapshot with empty distro.
	}

	family := classifyDistro(distro)

	var packages []installedPackage
	switch family {
	case pkgFamilyDebian:
		packages, err = collectDebianPackages(ctx)
		if err != nil {
			c.logger.Warn("dpkg-query failed", "error", err)
		}
	case pkgFamilyRHEL:
		packages, err = collectRHELPackages(ctx)
		if err != nil {
			c.logger.Warn("rpm query failed", "error", err)
		}
	default:
		c.unsupportedOnce.Do(func() {
			c.logger.Info("package collector: unsupported distro",
				"id", distro.ID, "id_like", distro.IDLike)
		})
	}

	collected := make([]metrics.Metric, 0, 3)

	addGauge := func(name string, value float64, labels map[string]string) {
		m, err := c.builder.GaugeWithLabels(name, value, labels)
		if err != nil {
			c.logger.Warn("failed to build metric", "name", name, "error", err)
			return
		}
		collected = append(collected, m)
	}

	source := ""
	switch family {
	case pkgFamilyDebian:
		source = "dpkg"
	case pkgFamilyRHEL:
		source = "rpm"
	}

	// Distro identifier metric. The CVE matcher uses these labels to pick
	// the right vulnerability feed (Ubuntu USN vs RHEL/RHSA vs Debian DSA, etc.).
	distroLabels := map[string]string{
		"distro_id":         distro.ID,
		"distro_version_id": distro.VersionID,
	}
	if distro.IDLike != "" {
		distroLabels["distro_id_like"] = distro.IDLike
	}
	addGauge("security_packages_distro_id", 1.0, distroLabels)

	// Count gauge.
	countLabels := map[string]string{}
	if source != "" {
		countLabels["source"] = source
	}
	addGauge("security_installed_package_count", float64(len(packages)), countLabels)

	// Structured snapshot: the inventory travels in the payload's top-level
	// `snapshots` array. The platform persists it into
	// host_security_snapshots, where cve-matcher.ts joins it against the
	// distro advisory feeds. Shape must match InstalledPackagesSnapshot in
	// platform/lib/security/findings-types.ts.
	//
	// Emitted only when we actually enumerated something. An empty inventory
	// means the query failed or the distro is unsupported; publishing that
	// would let the matcher conclude the host has no packages — and therefore
	// no vulnerabilities — which is worse than having no snapshot at all.
	if len(packages) > 0 {
		c.store(collected, metrics.Snapshot{
			Type: metrics.SnapshotInstalledPackages,
			Payload: map[string]any{
				"packages":          packages,
				"distro_id":         distro.ID,
				"distro_version_id": distro.VersionID,
			},
		})
	} else {
		// Cache the gauges so throttled cycles stay continuous, but leave
		// pending nil so no misleading snapshot is published.
		c.store(collected, metrics.Snapshot{})
		c.clearPending()
	}

	c.logger.Debug("installed packages collected",
		"count", len(packages),
		"source", source,
		"distro_id", distro.ID,
		"distro_version_id", distro.VersionID)

	return collected, nil
}

// readOSRelease parses /etc/os-release, extracting ID, ID_LIKE, and
// VERSION_ID. Quote handling matches the os-release(5) spec.
func readOSRelease(path string) (distroInfo, error) {
	var d distroInfo

	f, err := os.Open(path)
	if err != nil {
		return d, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := line[:eq]
		val := strings.Trim(line[eq+1:], `"`)
		switch key {
		case "ID":
			d.ID = strings.ToLower(val)
		case "ID_LIKE":
			d.IDLike = strings.ToLower(val)
		case "VERSION_ID":
			d.VersionID = val
		}
	}
	if err := scanner.Err(); err != nil {
		return d, fmt.Errorf("scanning os-release: %w", err)
	}
	return d, nil
}

// collectDebianPackages runs `dpkg-query` once and parses tab-separated
// `name<TAB>version<TAB>arch` lines. The whole inventory comes back in one
// invocation — never one-call-per-package.
func collectDebianPackages(ctx context.Context) ([]installedPackage, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	path, err := exec.LookPath("dpkg-query")
	if err != nil {
		return nil, fmt.Errorf("dpkg-query not found: %w", err)
	}

	cmd := exec.CommandContext(cmdCtx, path, "-W", "-f=${Package}\t${Version}\t${Architecture}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}

	return parseDpkgOutput(string(out)), nil
}

// parseDpkgOutput splits the dpkg-query output into installedPackage rows.
func parseDpkgOutput(output string) []installedPackage {
	var pkgs []installedPackage

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		arch := strings.TrimSpace(parts[2])
		if name == "" {
			continue
		}
		pkgs = append(pkgs, installedPackage{
			Name:      name,
			Version:   version,
			Arch:      arch,
			Source:    "dpkg",
			Ecosystem: EcosystemDeb,
		})
	}

	return pkgs
}

// collectRHELPackages runs `rpm -qa` with a custom queryformat that yields
// `name<TAB>version-release<TAB>arch` lines. Single invocation for the full
// inventory.
func collectRHELPackages(ctx context.Context) ([]installedPackage, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	path, err := exec.LookPath("rpm")
	if err != nil {
		return nil, fmt.Errorf("rpm not found: %w", err)
	}

	cmd := exec.CommandContext(cmdCtx, path, "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}

	return parseRPMOutput(string(out)), nil
}

// parseRPMOutput splits rpm -qa output into installedPackage rows.
func parseRPMOutput(output string) []installedPackage {
	var pkgs []installedPackage

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		arch := strings.TrimSpace(parts[2])
		if name == "" {
			continue
		}
		pkgs = append(pkgs, installedPackage{
			Name:      name,
			Version:   version,
			Arch:      arch,
			Source:    "rpm",
			Ecosystem: EcosystemRPM,
		})
	}

	return pkgs
}
