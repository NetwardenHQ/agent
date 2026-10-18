// Package security: cross-platform shell of the installed-package inventory
// collector. The Linux-specific data gathering lives in packages_linux.go;
// non-Linux builds get a no-op shell from packages_nonlinux.go.
package security

import (
	"log/slog"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// PackagesCollector enumerates installed packages (dpkg or rpm) and emits a
// single snapshot metric carrying the per-package payload as a JSON-encoded
// label value, plus a count gauge and a distro identifier metric. It runs
// every 6 hours because package state rarely changes and the platform CVE
// matcher reads the most recent snapshot.
type PackagesCollector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder

	// One-time log lines (e.g. "unsupported distro"), so they are not
	// repeated every collection cycle.
	unsupportedOnce sync.Once

	// Cadence and snapshot handoff. Enumerating dpkg/rpm and shipping the
	// inventory is the heaviest thing this agent does (~50KB of JSON on a
	// modest server, ~150KB on a large one), and package state changes on
	// the order of days. lastCollected gates the real work
	// to PackagesCollectionInterval; lastMetrics is re-emitted with fresh
	// timestamps on intervening cycles so the count/distro gauges stay
	// continuous instead of leaving holes in the time series.
	mu            sync.Mutex
	lastCollected time.Time
	lastMetrics   []metrics.Metric
	pending       *metrics.Snapshot

	// Language-package discovery (Linux only), on by default and controlled
	// by enable_security_lang_packages. langRoots are operator-configured
	// directories to scan for node_modules and site-packages in addition to
	// the auto-discovered Python locations.
	langPackages bool
	langRoots    []string
}

// NewPackagesCollector creates a new installed-package inventory collector.
func NewPackagesCollector(hostname string, opts ...PackagesOption) *PackagesCollector {
	c := &PackagesCollector{
		hostname: hostname,
		logger:   slog.Default(),
		builder:  metrics.NewBuilder().WithHostname(hostname),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// PackagesOption configures the packages collector.
type PackagesOption func(*PackagesCollector)

// WithLangPackages enables host-installed language-package discovery
// and sets any extra roots to scan (for node_modules and
// non-system site-packages). Auto-discovered Python system locations are
// always included when enabled.
func WithLangPackages(enabled bool, roots []string) PackagesOption {
	return func(c *PackagesCollector) {
		c.langPackages = enabled
		c.langRoots = roots
	}
}

// WithPackagesLogger sets the logger for the packages collector.
func WithPackagesLogger(logger *slog.Logger) PackagesOption {
	return func(c *PackagesCollector) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// Name returns the collector name.
func (c *PackagesCollector) Name() string {
	return "security_packages"
}

// Close releases collector resources (none currently held).
func (c *PackagesCollector) Close() error {
	c.logger.Debug("packages collector closed")
	return nil
}

// PackagesCollectionInterval is the recommended scheduling cadence for this
// collector. The collector throttles itself to it, since the registry runs
// every collector on a single global interval.
const PackagesCollectionInterval = 6 * time.Hour

// Package ecosystems. An ecosystem is the namespace a package belongs to,
// distinct from Source, the tool that reported it (dpkg is a tool, deb is a
// format). It decides which vulnerability feed applies: operating-system
// ecosystems map to the distro advisory feeds (Ubuntu USN, Debian DSA, Red Hat
// OVAL), language ecosystems to OSV, whose ecosystem identifiers they match.
// The Linux language walk (langpkg_unix.go) emits npm and pypi; the rest are
// reserved.
const (
	// Operating-system package ecosystems.
	EcosystemDeb = "deb"
	EcosystemRPM = "rpm"
	EcosystemAPK = "apk"

	// Language package ecosystems (npm and pypi emitted; others reserved).
	EcosystemNPM      = "npm"
	EcosystemPyPI     = "pypi"
	EcosystemRubyGems = "rubygems"
	EcosystemGoMod    = "gomod"
	EcosystemCargo    = "cargo"
	EcosystemMaven    = "maven"
	EcosystemNuGet    = "nuget"
	EcosystemComposer = "composer"
)

// installedPackage describes a single installed package. The JSON tags are
// part of the agent API and must stay stable. name, version, distro_id and
// distro_version_id together form the CVE join key.
type installedPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Arch      string `json:"arch"`
	Source    string `json:"source"`    // tool that reported it: "dpkg" | "rpm"
	Ecosystem string `json:"ecosystem"` // package namespace: see the Ecosystem* constants
}

// distroInfo carries the /etc/os-release fields the platform CVE matcher
// needs to pick the right vulnerability feed.
type distroInfo struct {
	ID        string // ID=, e.g. "ubuntu"
	IDLike    string // ID_LIKE=, e.g. "debian"
	VersionID string // VERSION_ID=, e.g. "22.04"
}

// pkgFamily classifies a distro into the package-manager family to query.
type pkgFamily int

const (
	pkgFamilyUnknown pkgFamily = iota
	pkgFamilyDebian
	pkgFamilyRHEL
)

// classifyDistro inspects /etc/os-release ID + ID_LIKE values and returns
// the package-manager family to use, or pkgFamilyUnknown when none match.
func classifyDistro(d distroInfo) pkgFamily {
	candidates := []string{d.ID, d.IDLike}
	debianFamily := map[string]bool{
		"debian": true, "ubuntu": true, "raspbian": true, "linuxmint": true,
		"pop": true, "elementary": true, "kali": true, "neon": true,
		"deepin": true, "zorin": true, "parrot": true,
	}
	rhelFamily := map[string]bool{
		"rhel": true, "centos": true, "fedora": true, "rocky": true,
		"almalinux": true, "ol": true, "oracle": true, "amzn": true,
		"amazonlinux": true, "scientific": true,
	}
	for _, c := range candidates {
		// ID_LIKE may be a space-separated list.
		for _, tok := range splitSpaces(c) {
			tok = lower(tok)
			if debianFamily[tok] {
				return pkgFamilyDebian
			}
			if rhelFamily[tok] {
				return pkgFamilyRHEL
			}
		}
	}
	return pkgFamilyUnknown
}

// splitSpaces splits on whitespace without importing strings into this
// cross-platform file.
func splitSpaces(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		isSpace := c == ' ' || c == '\t'
		if isSpace {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

// lower lower-cases ASCII without importing strings into this
// cross-platform file.
func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// Verify interface compliance at compile time.
var _ metrics.Collector = (*PackagesCollector)(nil)

// Snapshots returns the installed-package inventory produced by the most
// recent real enumeration, then clears it. Throttled cycles return nil: the
// platform already holds the inventory, and re-shipping an unchanged 50KB
// payload every cycle would dominate the agent's upload volume.
func (c *PackagesCollector) Snapshots() []metrics.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pending == nil {
		return nil
	}
	snap := *c.pending
	c.pending = nil
	return []metrics.Snapshot{snap}
}

// shouldCollect reports whether the inventory is due for re-enumeration and
// records the attempt. Returns the cached metrics to re-emit when throttled.
func (c *PackagesCollector) shouldCollect(now time.Time) (due bool, cached []metrics.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastCollected.IsZero() || now.Sub(c.lastCollected) >= PackagesCollectionInterval {
		c.lastCollected = now
		return true, nil
	}
	return false, c.lastMetrics
}

// store records the results of a real enumeration for later reuse.
func (c *PackagesCollector) store(collected []metrics.Metric, snap metrics.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastMetrics = collected
	c.pending = &snap
}

// clearPending drops any staged snapshot without touching the cached metrics.
// Used when enumeration produced no packages, so a throttled cycle still
// re-emits gauges but nothing misleading reaches the findings evaluator.
func (c *PackagesCollector) clearPending() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = nil
}
