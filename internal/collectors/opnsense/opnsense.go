// Package opnsense collects the state that only an OPNsense firewall has:
// gateway health, firmware and package updates, the pf state table, Suricata
// (IDS/IPS) alerts, the firewall and audit logs, CARP, and configuration
// changes.
//
// It reads what OPNsense itself writes (its firmware status file, its log
// files, its configd actions) and never changes anything. A source that cannot
// be read produces a warning and no metrics for that source: a monitoring
// platform must never see a zero that was really "unknown".
//
// The collector is inert on any host that is not OPNsense (Enabled reports
// false), so it compiles and its parsers are tested on every platform.
package opnsense

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Paths and commands OPNsense provides. They are fields of the collector, not
// constants, so tests can point them at fixtures.
const (
	defaultConfigXML     = "/conf/config.xml"
	defaultBackupDir     = "/conf/backup"
	defaultFirmwareJSON  = "/tmp/pkg_upgrade.json"
	defaultEveJSON       = "/var/log/suricata/eve.json"
	defaultSuricataPID   = "/var/run/suricata.pid"
	defaultFilterLogDir  = "/var/log/filter"
	defaultAuditLogDir   = "/var/log/audit"
	defaultVersionMarker = "/usr/local/opnsense/version/core"
	commandTimeout       = 3 * time.Second
)

// Collector gathers OPNsense-specific metrics.
type Collector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder

	configXML     string
	backupDir     string
	firmwareJSON  string
	firmwareOwner uint32 // uid that must own firmwareJSON (root)
	eveJSON       string
	suricataPID   string
	filterLogDir  string
	auditLogDir   string
	versionMarker string
	crowdsecBin   string
	crowdsecCfg   string

	// run executes a command and returns its stdout. Swapped in tests.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
	now func() time.Time

	mu     sync.Mutex
	warned map[string]string
	cfg    *configInfo
	eve    *tailer
	filter *tailer
	audit  *tailer
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

// NewCollector creates the OPNsense collector.
func NewCollector(hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname:      hostname,
		logger:        slog.Default(),
		builder:       metrics.NewBuilder().WithHostname(hostname),
		configXML:     defaultConfigXML,
		backupDir:     defaultBackupDir,
		firmwareJSON:  defaultFirmwareJSON,
		eveJSON:       defaultEveJSON,
		suricataPID:   defaultSuricataPID,
		filterLogDir:  defaultFilterLogDir,
		auditLogDir:   defaultAuditLogDir,
		versionMarker: defaultVersionMarker,
		crowdsecBin:   defaultCrowdSecBin,
		crowdsecCfg:   defaultCrowdSecCfg,
		run:           runCommand,
		now:           time.Now,
		warned:        map[string]string{},
	}
	for _, opt := range opts {
		opt(c)
	}
	c.eve = newTailer(func(time.Time) string { return c.eveJSON })
	c.filter = newTailer(func(t time.Time) string { return dailyLog(c.filterLogDir, "filter", t) })
	c.audit = newTailer(func(t time.Time) string { return dailyLog(c.auditLogDir, "audit", t) })
	return c
}

// Name returns the collector name.
func (c *Collector) Name() string { return "opnsense" }

// Enabled reports whether this host is an OPNsense firewall. OPNsense ships
// /usr/local/opnsense/version/core and keeps its configuration in
// /conf/config.xml; a plain FreeBSD host has neither.
func (c *Collector) Enabled() bool {
	for _, p := range []string{c.versionMarker, c.configXML} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// Close releases nothing; the collector holds no open files between cycles.
func (c *Collector) Close() error { return nil }

// Collect runs every source. A failing source is logged (once per distinct
// failure) and contributes no metrics; Collect errors only when every source
// failed, so the registry records a failed cycle instead of an empty one.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	ts := c.now()
	c.cfg = nil
	em := &emitter{c: c, ts: ts}

	sources := []struct {
		name string
		fn   func(context.Context, *emitter) error
	}{
		// File sources first: they are fast, and ids needs config. The
		// command sources follow, each command under commandTimeout, so a
		// hung configctl cannot starve the rest of the cycle's budget.
		{"config", c.collectConfig},
		{"firmware", c.collectFirmware},
		{"ids", c.collectIDS},
		{"filterlog", c.collectFilterLog},
		{"auth", c.collectAuth},
		{"gateways", c.collectGateways},
		{"pf", c.collectPF},
		{"carp", c.collectCARP},
	}

	var failed []error
	for _, s := range sources {
		if err := s.fn(ctx, em); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", s.name, err))
			c.warnOnce(s.name, err)
		}
	}
	if len(failed) == len(sources) {
		return nil, errors.Join(failed...)
	}
	return em.out, nil
}

// warnOnce logs a source failure the first time it is seen, and again only
// when the message changes, so a persistent fault does not flood the log.
func (c *Collector) warnOnce(source string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.warned[source] == err.Error() {
		return
	}
	c.warned[source] = err.Error()
	c.logger.Warn("opnsense source unavailable; no metrics emitted for it", "source", source, "error", err)
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %v: %w: %s", name, args, err, strings.ToValidUTF8(stderr.String(), "?"))
	}
	return out, nil
}

// limitedBuffer keeps the first 512 bytes of stderr for error messages.
type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := 512 - len(l.b); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.b = append(l.b, p[:room]...)
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return string(l.b) }

// emitter accumulates metrics for one cycle.
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

var _ metrics.Collector = (*Collector)(nil)
