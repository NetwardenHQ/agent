//go:build darwin || windows || freebsd

package security

import (
	"context"
	"strings"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Enabled returns true: listening-socket enumeration is available on macOS,
// FreeBSD and Windows. collectListeningSockets reads sockstat(1) on FreeBSD
// (ports_source_freebsd.go) and gopsutil elsewhere (ports_source_gopsutil.go),
// which uses lsof on Darwin and GetExtendedTcpTable/GetExtendedUdpTable on
// Windows.
func (c *PortsCollector) Enabled() bool {
	return true
}

// Collect enumerates listening TCP/UDP sockets and emits the same
// security_* gauge family and listening_ports snapshot as the Linux
// implementation. The classification helpers (isPublicBindAddr,
// managementPorts) are shared, so a public bind on port 3389 is scored
// identically regardless of platform.
func (c *PortsCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	c.logger.Debug("collecting listening sockets")

	timestamp := time.Now()
	c.builder = c.builder.WithTimestamp(timestamp)

	sockets, err := collectListeningSockets(ctx)
	if err != nil {
		c.logger.Warn("failed to enumerate listening sockets", "error", err)
		return nil, nil
	}
	if len(sockets) == 0 {
		// An empty result is far more likely a permissions or tooling
		// problem than a host with nothing listening. Emit nothing rather
		// than a false all-clear.
		c.logger.Warn("listening-socket enumeration returned nothing; skipping cycle")
		return nil, nil
	}

	totalCount, publicCount, loopbackCount, managementOpen, managementParts := classifySockets(sockets)

	collected := make([]metrics.Metric, 0, 4)
	addGauge := func(name string, value float64, labels map[string]string) {
		m, err := c.builder.GaugeWithLabels(name, value, labels)
		if err != nil {
			c.logger.Warn("failed to build metric", "name", name, "error", err)
			return
		}
		collected = append(collected, m)
	}

	baseLabels := func() map[string]string {
		return map[string]string{"source": portsSource}
	}

	addGauge("security_open_ports_count", float64(totalCount), baseLabels())
	addGauge("security_public_bind_count", float64(publicCount), baseLabels())
	addGauge("security_loopback_bind_count", float64(loopbackCount), baseLabels())

	managementLabels := baseLabels()
	if len(managementParts) > 0 {
		managementLabels["ports"] = strings.Join(managementParts, ",")
	}
	addGauge("security_management_ports_public", float64(managementOpen), managementLabels)

	c.setPending(metrics.Snapshot{
		Type: metrics.SnapshotListeningPorts,
		Payload: map[string]any{
			"ports":                   sockets,
			"open_ports_count":        totalCount,
			"public_bind_count":       publicCount,
			"loopback_bind_count":     loopbackCount,
			"management_ports_public": managementOpen,
		},
	})

	c.logger.Debug("listening sockets collected",
		"count", totalCount,
		"public", publicCount,
		"loopback", loopbackCount,
		"management_public", managementOpen)

	return collected, nil
}

// normalizeBindAddr converts platform-specific wildcard spellings to the ones
// isPublicBindAddr recognizes. Windows reports the IPv4 wildcard as "0.0.0.0"
// and the IPv6 wildcard as "::", but lsof on Darwin renders both as "*", and
// an empty string shows up for some UDP rows.
func normalizeBindAddr(ip string) string {
	switch ip {
	case "", "*":
		return "0.0.0.0"
	}
	return ip
}
