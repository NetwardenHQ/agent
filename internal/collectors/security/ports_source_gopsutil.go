//go:build darwin || windows

package security

import (
	"context"
	"fmt"
	"strings"
	"syscall"

	gopsnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// portsSource labels the metrics with where the sockets came from.
const portsSource = "gopsutil"

// collectListeningSockets enumerates listening sockets through gopsutil.
func collectListeningSockets(ctx context.Context) ([]listeningSocket, error) {
	return collectListeningSocketsGopsutil(ctx)
}

// collectListeningSocketsGopsutil returns the listening sockets reported by
// gopsutil, normalized into the same listeningSocket shape the Linux parsers
// produce.
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

// processName resolves a PID to a process name, caching results. A failure
// (the process exited, or the agent lacks the rights to inspect it) yields an
// empty name, as on Linux where non-root agents see redacted process info.
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
