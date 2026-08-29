// Package security: cross-platform shell of the listening-port audit collector.
// The Linux-specific data gathering lives in ports_linux.go; non-Linux builds
// get a no-op shell from ports_nonlinux.go.
package security

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"netwarden/internal/metrics"
)

// PortsCollector enumerates listening TCP/UDP sockets and emits aggregate
// gauges plus a single snapshot metric carrying the per-socket payload as a
// JSON-encoded label value (see snapshotLabel constant). Cadence: every 5
// minutes — runtime listening state changes rarely.
type PortsCollector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder

	// Snapshot handoff. Collect() runs on the worker pool and stores the
	// listening-socket table here; Snapshots() is called afterwards on the
	// agent goroutine and drains it. Guarded because those are different
	// goroutines.
	mu      sync.Mutex
	pending *metrics.Snapshot
}

// NewPortsCollector creates a new listening-port audit collector.
func NewPortsCollector(hostname string, opts ...PortsOption) *PortsCollector {
	c := &PortsCollector{
		hostname: hostname,
		logger:   slog.Default(),
		builder:  metrics.NewBuilder().WithHostname(hostname),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// PortsOption configures the ports collector.
type PortsOption func(*PortsCollector)

// WithPortsLogger sets the logger for the ports collector.
func WithPortsLogger(logger *slog.Logger) PortsOption {
	return func(c *PortsCollector) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// Name returns the collector name.
func (c *PortsCollector) Name() string {
	return "security_ports"
}

// Close releases collector resources (none currently held).
func (c *PortsCollector) Close() error {
	c.logger.Debug("ports collector closed")
	return nil
}

// PortsCollectionInterval documents the slowest acceptable cadence for
// listening-port auditing. This collector deliberately runs on the agent's
// global reporting interval (default 60s) instead: `ss` is a single cheap
// exec, the snapshot is a few KB, and a newly exposed management port is the
// finding that most needs to be caught quickly. The constant is the ceiling
// a future per-collector scheduler must not exceed, not the current cadence.
const PortsCollectionInterval = 5 * time.Minute

// Canonical protocol values. The platform contract (ListeningPortEntry.proto
// in lib/security/findings-types.ts) expects exactly "tcp" or "udp".
const (
	protoTCP = "tcp"
	protoUDP = "udp"
)

// listeningSocket describes a single listening socket. Field tags are
// shared with the platform-side payload contract — keep them stable.
type listeningSocket struct {
	Proto       string `json:"proto"`        // "tcp" | "udp"
	Port        int    `json:"port"`         // 0..65535
	BindAddr    string `json:"bind_addr"`    // e.g. "0.0.0.0", "::", "127.0.0.1"
	ProcessName string `json:"process_name"` // empty when redacted (non-root)
	PID         int    `json:"pid"`          // 0 when redacted
}

// managementPorts is the canonical list of high-value management ports
// flagged when bound publicly. Mirrors the spec exactly — keep in sync with
// platform-side CVE/exposure rules.
var managementPorts = map[int]string{
	22:    "ssh",
	3389:  "rdp",
	5432:  "postgres",
	3306:  "mysql",
	27017: "mongodb",
	6379:  "redis",
	9200:  "elasticsearch",
	5601:  "kibana",
	2375:  "docker",
	2376:  "docker-tls",
}

// isPublicBindAddr reports whether the given bind address means "all
// interfaces" (i.e., reachable from the network). Both IPv4 0.0.0.0 and
// IPv6 :: count, plus the rare blank-address case some kernels emit.
func isPublicBindAddr(addr string) bool {
	switch stripZone(addr) {
	case "0.0.0.0", "::", "*", "":
		return true
	}
	return false
}

// stripZone removes a scope/zone identifier from a bind address.
//
// The kernel appends "%<iface>" when a socket is bound to a specific
// interface — IPv6 link-local addresses always carry one (fe80::1%eth0), and
// so do IPv4 sockets using SO_BINDTODEVICE, which is how dnsmasq on a libvirt
// bridge shows up as "0.0.0.0%virbr0". Without stripping, such a wildcard
// bind matched neither the public nor the loopback case and silently fell out
// of both counters — observed live on a host running libvirt.
func stripZone(addr string) string {
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// isLoopbackBindAddr reports whether the given bind address is loopback-only.
func isLoopbackBindAddr(addr string) bool {
	addr = stripZone(addr)
	switch addr {
	case "127.0.0.1", "::1":
		return true
	}
	// The whole 127.0.0.0/8 range is loopback, not just 127.0.0.1 —
	// systemd-resolved binds 127.0.0.53, for instance.
	return strings.HasPrefix(addr, "127.")
}

// Verify interface compliance at compile time.
var _ metrics.Collector = (*PortsCollector)(nil)

// Snapshots returns the listening-ports snapshot produced by the most recent
// Collect(), then clears it so a stalled or throttled cycle never re-ships a
// stale socket table under a fresh timestamp.
func (c *PortsCollector) Snapshots() []metrics.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pending == nil {
		return nil
	}
	snap := *c.pending
	c.pending = nil
	return []metrics.Snapshot{snap}
}

// setPending stores the snapshot for the next Snapshots() call.
func (c *PortsCollector) setPending(snap metrics.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = &snap
}

// classifySockets scores a socket table into the aggregate counters the
// gauges and the listening_ports snapshot both report. Shared by every
// platform implementation so a public bind on a management port is judged
// identically on Linux, macOS, and Windows.
//
// managementParts is a human-readable "name/port" list surfaced as a metric
// label, deduplicated because the same port routinely appears twice (once on
// the IPv4 wildcard and once on the IPv6 one).
func classifySockets(sockets []listeningSocket) (total, public, loopback, management int, managementParts []string) {
	total = len(sockets)
	seenManagement := make(map[int]struct{})

	for _, s := range sockets {
		isPublic := isPublicBindAddr(s.BindAddr)
		switch {
		case isPublic:
			public++
		case isLoopbackBindAddr(s.BindAddr):
			loopback++
			// Loopback-bound management services are not exposed; skip them.
			continue
		}

		// A management port counts as exposed when it is bound to anything
		// other than loopback — a wildcard bind or a specific routable
		// address both reach the network.
		name, isManagement := managementPorts[s.Port]
		if !isManagement {
			continue
		}
		if _, dup := seenManagement[s.Port]; dup {
			continue
		}
		seenManagement[s.Port] = struct{}{}
		management++
		managementParts = append(managementParts, name+"/"+strconv.Itoa(s.Port))
	}

	return total, public, loopback, management, managementParts
}
