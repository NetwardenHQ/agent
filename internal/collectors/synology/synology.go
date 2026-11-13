// Package synology reports the health of a Synology NAS: drives, RAID,
// volumes, the UPS and, when the owner sets up the optional status task,
// Security Advisor, DSM updates, abnormal sign-ins and containers.
//
// DSM 7 runs third-party packages as an unprivileged user. Drive state
// (DSM's own per-drive files under /run/synostorage), RAID (/proc/mdstat),
// mounts and the UPS (DSM's UPS service on localhost) are readable by that
// user, so the agent reads them directly. Security Advisor, sign-in history,
// the update check and Container Manager are root-only; they come from a
// status task the owner may create in DSM's Task Scheduler, which writes the
// replies of DSM's own APIs into a root-owned directory (docs/synology.md).
// The agent never runs anything as root.
package synology

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/sharesnap"
)

const (
	// DefaultStatusDir is where the DSM status task writes its files.
	DefaultStatusDir = "/var/lib/netwarden-dsm"
	defaultMarker    = "/etc.defaults/synoinfo.conf"
	defaultMdstat    = "/proc/mdstat"
	defaultMounts    = "/proc/mounts"
	defaultDisksDir  = "/run/synostorage/disks"
	defaultHwmonDir  = "/sys/class/hwmon"
	defaultUPSAddr   = "127.0.0.1:3493"
	// maxStatusFile bounds each file; the storage reply of a 24-bay unit is
	// around 200 KiB.
	maxStatusFile = 4 << 20
	// freshFor is how old a status file may be: the task runs every five
	// minutes. The update check asks Synology's servers, so the task runs it
	// hourly.
	freshFor        = 20 * time.Minute
	upgradeFreshFor = 3 * time.Hour
	// localSources is how many sources at the head of Collect's list need no
	// status task.
	localSources = 6
)

// Collector gathers Synology DSM metrics.
type Collector struct {
	hostname  string
	logger    *slog.Logger
	builder   metrics.MetricBuilder
	statusDir string
	marker    string
	mdstat    string
	mounts    string
	disksDir  string
	hwmonDir  string
	upsAddr   string
	volumes   string
	owner     uint32
	now       func() time.Time

	mu sync.Mutex
	// lastLogin is the newest abnormal sign-in already reported, as a Unix
	// time. Zero until the first read, which only sets the baseline.
	lastLogin int64
	baselined bool
	warned    map[string]string
}

// Option configures the collector.
type Option func(*Collector)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *Collector) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithStatusDir sets where the DSM status task writes its files.
func WithStatusDir(dir string) Option {
	return func(c *Collector) {
		if dir != "" {
			c.statusDir = dir
		}
	}
}

// NewCollector creates the Synology collector.
func NewCollector(hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname:  hostname,
		logger:    slog.Default(),
		builder:   metrics.NewBuilder().WithHostname(hostname),
		statusDir: DefaultStatusDir,
		marker:    defaultMarker,
		mdstat:    defaultMdstat,
		mounts:    defaultMounts,
		disksDir:  defaultDisksDir,
		hwmonDir:  defaultHwmonDir,
		upsAddr:   defaultUPSAddr,
		volumes:   sharesnap.DefaultVolumes,
		owner:     0,
		now:       time.Now,
		warned:    map[string]string{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Name returns the collector name.
func (c *Collector) Name() string { return "synology" }

// Enabled reports whether this host runs DSM.
func (c *Collector) Enabled() bool {
	_, err := os.Stat(c.marker)
	return err == nil
}

// Close releases nothing.
func (c *Collector) Close() error { return nil }

type emitter struct {
	c   *Collector
	ts  time.Time
	out []metrics.Metric
}

func (e *emitter) gauge(name string, value float64, labels map[string]string) {
	m, err := e.c.builder.WithTimestamp(e.ts).GaugeWithLabels(name, value, labels)
	if err != nil {
		e.c.logger.Warn("failed to create gauge metric", "name", name, "error", err)
		return
	}
	e.out = append(e.out, m)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Collect reads every source. A missing or untrusted file contributes no
// metrics for its source; Collect errors only when every source failed.
func (c *Collector) Collect(_ context.Context) ([]metrics.Metric, error) {
	e := &emitter{c: c, ts: c.now()}

	// Whether the status task is running at all, and how fresh its files
	// are: without it every DSM-side number below simply stops arriving.
	newest, present := c.newestStatus()
	e.gauge("synology_status_present", b2f(present), nil)
	if present {
		e.gauge("synology_status_age_seconds", e.ts.Sub(newest).Seconds(), nil)
	}

	sources := []struct {
		name string
		fn   func(*emitter) error
	}{
		// Readable by the package user.
		{"disks", c.collectDisks},
		{"mdstat", c.collectMdstat},
		{"volumes", c.collectVolumes},
		{"temperature", c.collectTemperature},
		{"ups", c.collectUPS},
		{"snapshots", c.collectSnapshots},
		// Written by the optional root status task (after the first localSources).
		{"security_scan", c.fileSource("security_scan.json", freshFor, collectSecurityScan)},
		{"upgrade", c.fileSource("upgrade.json", upgradeFreshFor, collectUpgrade)},
		{"login_activity", c.fileSource("login_activity.json", freshFor, c.collectLogins)},
		{"containers", c.fileSource("containers.json", freshFor, collectContainers)},
	}
	var failed []error
	for i, s := range sources {
		// Without the status task its sources are simply not set up.
		if !present && i >= localSources {
			continue
		}
		if err := s.fn(e); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", s.name, err))
			c.warnOnce(s.name, err)
		}
	}
	if len(failed) == len(sources) || (!present && len(failed) == localSources) {
		return nil, errors.Join(failed...)
	}
	return e.out, nil
}

// fileSource reads one status file and hands its bytes to parse. A file
// older than maxAge is not current: the task keeps the last good reply when a
// call fails, so an old file means that call has been failing.
func (c *Collector) fileSource(name string, maxAge time.Duration, parse func(*emitter, []byte) error) func(*emitter) error {
	return func(e *emitter) error {
		data, info, err := readTrustedFile(filepath.Join(c.statusDir, name), c.owner, maxStatusFile)
		if err != nil {
			return err
		}
		if age := e.ts.Sub(info.ModTime()); age > maxAge {
			return fmt.Errorf("%s was last written %s ago", name, age.Round(time.Minute))
		}
		return parse(e, data)
	}
}

// newestStatus is the modification time of the newest status file.
func (c *Collector) newestStatus() (time.Time, bool) {
	entries, err := os.ReadDir(c.statusDir)
	if err != nil {
		return time.Time{}, false
	}
	var newest time.Time
	for _, ent := range entries {
		if !ent.Type().IsRegular() {
			continue
		}
		info, err := ent.Info()
		if err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, !newest.IsZero()
}

// warnOnce logs a source failure the first time it is seen, and again only
// when the message changes.
func (c *Collector) warnOnce(source string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.warned[source] == err.Error() {
		return
	}
	c.warned[source] = err.Error()
	c.logger.Warn("synology source unavailable; no metrics emitted for it", "source", source, "error", err)
}

var _ metrics.Collector = (*Collector)(nil)

func unix(sec int64) time.Time { return time.Unix(sec, 0) }
