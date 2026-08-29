//go:build darwin || windows

package security

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"netwarden/internal/metrics"
)

// Enabled returns true — listening-socket enumeration is available on macOS
// and Windows through gopsutil, which reads lsof on Darwin and the
// GetExtendedTcpTable/GetExtendedUdpTable APIs on Windows.
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

	sockets, err := collectListeningSocketsGopsutil(ctx)
	if err != nil {
		c.logger.Warn("failed to enumerate listening sockets", "error", err)
		return nil, nil
	}
	if len(sockets) == 0 {
		// Same reasoning as the Linux path: an empty result is far more
		// likely to be a permissions or tooling problem than a host with
		// nothing listening, and "0 exposed ports" is a dangerous thing to
		// report wrongly. Emit nothing rather than a false all-clear.
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
		return map[string]string{"source": "gopsutil"}
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

// collectListeningSocketsGopsutil returns the listening sockets reported by
// gopsutil, normalized into the same listeningSocket shape the Linux parsers
// produce so the platform contract is identical across operating systems.
func collectListeningSocketsGopsutil(ctx context.Context) ([]listeningSocket, error) {
	conns, err := gopsnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate connections: %w", err)
	}

	// Process names are resolved lazily and cached: a host can have many
	// sockets owned by the same PID, and each lookup is a syscall (or an
	// lsof-backed read on Darwin).
	nameCache := make(map[int32]string)

	sockets := make([]listeningSocket, 0, len(conns))
	for _, conn := range conns {
		proto, ok := protoFromSockType(conn.Type)
		if !ok {
			continue
		}

		// TCP sockets must be in LISTEN state. UDP is connectionless and
		// carries no meaningful state, so every UDP row is a bound port.
		if proto == protoTCP && !strings.EqualFold(conn.Status, "LISTEN") {
			continue
		}
		if conn.Laddr.Port == 0 || conn.Laddr.Port > 65535 {
			continue
		}

		sockets = append(sockets, listeningSocket{
			Proto:       proto,
			Port:        int(conn.Laddr.Port),
			BindAddr:    normalizeBindAddr(conn.Laddr.IP),
			ProcessName: processName(ctx, conn.Pid, nameCache),
			PID:         int(conn.Pid),
		})
	}

	return sockets, nil
}

// protoFromSockType maps a socket type to the canonical protocol string.
// gopsutil sets SOCK_STREAM/SOCK_DGRAM consistently on both Darwin and
// Windows.
func protoFromSockType(sockType uint32) (string, bool) {
	switch sockType {
	case syscall.SOCK_STREAM:
		return protoTCP, true
	case syscall.SOCK_DGRAM:
		return protoUDP, true
	}
	return "", false
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

// processName resolves a PID to a process name, caching results. A failure is
// normal — the process may have exited, or the agent may lack the rights to
// inspect it — and yields an empty name, matching the Linux behaviour where
// non-root agents see redacted process info.
func processName(ctx context.Context, pid int32, cache map[int32]string) string {
	if pid <= 0 {
		return ""
	}
	if name, ok := cache[pid]; ok {
		return name
	}

	name := ""
	if proc, err := process.NewProcessWithContext(ctx, pid); err == nil {
		if n, err := proc.NameWithContext(ctx); err == nil {
			name = n
		}
	}
	cache[pid] = name
	return name
}
