package security

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"netwarden/internal/metrics"
)

// sshConfigInterval is how often the SSH config is re-parsed. Configs change
// rarely; an hour is plenty.
const sshConfigInterval = 1 * time.Hour

// SSHConfigCollector audits sshd_config for posture findings. It is invoked
// every collection cycle by the registry but only does real work once per
// hour (configs rarely change). Linux-only; non-Linux is a no-op.
type SSHConfigCollector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder

	// Throttling: we cache the last set of metrics and re-emit them with
	// fresh timestamps on intervening cycles, so dashboards stay populated
	// without re-parsing the file every minute.
	mu             sync.Mutex
	lastCollected  time.Time
	lastMetrics    []metrics.Metric
	pending        *metrics.Snapshot
	missingLogOnce sync.Once
}

// NewSSHConfigCollector creates a new SSH config audit collector.
func NewSSHConfigCollector(hostname string, opts ...SSHConfigOption) *SSHConfigCollector {
	c := &SSHConfigCollector{
		hostname: hostname,
		logger:   slog.Default(),
		builder:  metrics.NewBuilder().WithHostname(hostname),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SSHConfigOption configures the SSH config collector.
type SSHConfigOption func(*SSHConfigCollector)

// WithSSHConfigLogger sets the logger.
func WithSSHConfigLogger(logger *slog.Logger) SSHConfigOption {
	return func(c *SSHConfigCollector) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// Name returns the collector name.
func (c *SSHConfigCollector) Name() string {
	return "security_sshconfig"
}

// Close performs cleanup.
func (c *SSHConfigCollector) Close() error {
	c.logger.Debug("ssh config collector closed")
	return nil
}

// sshConfigFindings is the parsed form of sshd_config that the platform
// implementation produces and the cross-platform layer turns into metrics.
type sshConfigFindings struct {
	// Booleans (true => 1, false => 0). Each represents a posture finding
	// using "1 = noteworthy/insecure, 0 = secure" framing.
	PermitRootLogin bool
	PasswordAuth    bool
	ProtocolV1      bool
	X11Forwarding   bool
	PermitEmptyPass bool

	// Snapshot fields exposed via labels on a single posture-info metric.
	Port          string
	KexAlgorithms string
	Ciphers       string
	MACs          string

	// SourceFile is the resolved primary config path, used as a label so
	// operators can tell where findings originated (helpful when a host
	// uses a non-default location).
	SourceFile string
}

// addGauge / addGaugeWithLabels are duplicated locally so the SSH collector
// is self-contained.
func (c *SSHConfigCollector) addGauge(out *[]metrics.Metric, name string, value float64, ts time.Time) {
	m, err := c.builder.WithTimestamp(ts).Gauge(name, value)
	if err != nil {
		c.logger.Warn("failed to create gauge metric", "name", name, "error", err)
		return
	}
	*out = append(*out, m)
}

func (c *SSHConfigCollector) addGaugeWithLabels(out *[]metrics.Metric, name string, value float64, labels map[string]string, ts time.Time) {
	m, err := c.builder.WithTimestamp(ts).GaugeWithLabels(name, value, labels)
	if err != nil {
		c.logger.Warn("failed to create gauge metric with labels", "name", name, "error", err)
		return
	}
	*out = append(*out, m)
}

// boolToFloat converts a boolean posture flag to a metric value.
func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// emitMetrics builds the security_ssh_* gauge family from a findings struct.
func (c *SSHConfigCollector) emitMetrics(f sshConfigFindings, ts time.Time) []metrics.Metric {
	out := make([]metrics.Metric, 0, 6)

	c.addGauge(&out, "security_ssh_permit_root_login", boolToFloat(f.PermitRootLogin), ts)
	c.addGauge(&out, "security_ssh_password_auth", boolToFloat(f.PasswordAuth), ts)
	c.addGauge(&out, "security_ssh_protocol_v1", boolToFloat(f.ProtocolV1), ts)
	c.addGauge(&out, "security_ssh_x11_forwarding", boolToFloat(f.X11Forwarding), ts)
	c.addGauge(&out, "security_ssh_empty_passwords", boolToFloat(f.PermitEmptyPass), ts)

	// Posture snapshot — emits a single labeled metric carrying string
	// directives, mirroring how `system_info` exposes structured attributes.
	labels := map[string]string{
		"port":        f.Port,
		"source_file": f.SourceFile,
	}
	if f.KexAlgorithms != "" {
		labels["kex_algorithms"] = f.KexAlgorithms
	}
	if f.Ciphers != "" {
		labels["ciphers"] = f.Ciphers
	}
	if f.MACs != "" {
		labels["macs"] = f.MACs
	}
	c.addGaugeWithLabels(&out, "security_ssh_posture_info", 1.0, labels, ts)

	return out
}

// Verify interface compliance at compile time.
var _ metrics.Collector = (*SSHConfigCollector)(nil)

// Snapshots returns the sshd_config audit produced by the most recent real
// parse, then clears it. Throttled cycles return nil.
func (c *SSHConfigCollector) Snapshots() []metrics.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pending == nil {
		return nil
	}
	snap := *c.pending
	c.pending = nil
	return []metrics.Snapshot{snap}
}

// splitAlgoList turns an sshd_config algorithm directive into the string
// array the platform contract expects. sshd accepts comma-separated lists,
// optionally prefixed with +/-/^ to modify the built-in default set; the
// prefix is preserved because it changes the meaning and the server's crypto
// evaluator needs to see it verbatim. Returns nil (not an empty slice) for an
// absent directive, so the field is omitted rather than sent as [].
func splitAlgoList(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildSnapshot converts parsed findings into the SshConfigSnapshot shape
// defined in platform/lib/security/findings-types.ts. Note the type change on
// port: the agent parses it as a string (it comes out of a config file), but
// the contract declares `port?: number`, so it is converted here and omitted
// entirely when unparseable rather than sent as a string the server's Zod
// schema would reject.
func buildSSHConfigSnapshot(f sshConfigFindings) metrics.Snapshot {
	payload := map[string]any{
		"permit_root_login": f.PermitRootLogin,
		"password_auth":     f.PasswordAuth,
		"protocol_v1":       f.ProtocolV1,
		"x11_forwarding":    f.X11Forwarding,
		"empty_passwords":   f.PermitEmptyPass,
	}

	if port, err := strconv.Atoi(strings.TrimSpace(f.Port)); err == nil && port > 0 && port <= 65535 {
		payload["port"] = port
	}
	if kex := splitAlgoList(f.KexAlgorithms); kex != nil {
		payload["kex_algorithms"] = kex
	}
	if ciphers := splitAlgoList(f.Ciphers); ciphers != nil {
		payload["ciphers"] = ciphers
	}
	if macs := splitAlgoList(f.MACs); macs != nil {
		payload["macs"] = macs
	}

	return metrics.Snapshot{Type: metrics.SnapshotSSHConfig, Payload: payload}
}
