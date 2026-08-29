//go:build linux

package security

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"netwarden/internal/metrics"
)

// Enabled returns true on Linux — port auditing is unconditionally available.
func (c *PortsCollector) Enabled() bool {
	return true
}

// Collect enumerates listening TCP/UDP sockets and emits the aggregate gauges
// described in the security-wedge spec, plus a snapshot metric whose value is
// the total listening-socket count and whose `snapshot` label carries the
// JSON-encoded array of per-socket records.
func (c *PortsCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	c.logger.Debug("collecting listening sockets")

	timestamp := time.Now()
	c.builder = c.builder.WithTimestamp(timestamp)

	sockets, source, err := collectListeningSockets(ctx)
	if err != nil {
		c.logger.Warn("failed to enumerate listening sockets", "error", err)
		return nil, nil
	}

	totalCount, publicCount, loopbackCount, managementOpen, managementParts := classifySockets(sockets)

	collected := make([]metrics.Metric, 0, 5)

	addGauge := func(name string, value float64, labels map[string]string) {
		m, err := c.builder.GaugeWithLabels(name, value, labels)
		if err != nil {
			c.logger.Warn("failed to build metric", "name", name, "error", err)
			return
		}
		collected = append(collected, m)
	}

	baseLabels := func() map[string]string {
		return map[string]string{"source": source}
	}

	addGauge("security_open_ports_count", float64(totalCount), baseLabels())
	addGauge("security_public_bind_count", float64(publicCount), baseLabels())
	addGauge("security_loopback_bind_count", float64(loopbackCount), baseLabels())

	managementLabels := baseLabels()
	if len(managementParts) > 0 {
		managementLabels["ports"] = strings.Join(managementParts, ",")
	}
	addGauge("security_management_ports_public", float64(managementOpen), managementLabels)

	// Structured snapshot: the full socket table travels in the payload's
	// top-level `snapshots` array, NOT stuffed into a metric label. The
	// platform persists it into host_security_snapshots and runs
	// evaluateListeningPorts() against it. Shape must match
	// ListeningPortsSnapshot in platform/lib/security/findings-types.ts.
	//
	// `ports` is always a non-nil slice: json.Marshal renders a nil slice as
	// `null`, and the server's evaluator iterates it directly.
	portEntries := sockets
	if portEntries == nil {
		portEntries = []listeningSocket{}
	}
	c.setPending(metrics.Snapshot{
		Type: metrics.SnapshotListeningPorts,
		Payload: map[string]any{
			"ports":                   portEntries,
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
		"management_public", managementOpen,
		"source", source)

	return collected, nil
}

// collectListeningSockets runs `ss -tulnpH` and falls back to TCP-only `ss`
// or `netstat -tulnp` when needed. The second return value identifies which
// command produced the output (useful as a metric label and for debugging).
//
// A command that exits cleanly but whose output parses to zero sockets is
// treated as a FAILURE and we fall through to the next source. This is
// deliberate: reporting "0 listening ports" is indistinguishable from "this
// host is not exposed", which is exactly the false negative a security
// product must never emit. Any monitored host has at least one listening
// socket in practice; if every source genuinely yields nothing we return an
// error and the caller emits no metrics at all rather than a misleading zero.
func collectListeningSockets(ctx context.Context) ([]listeningSocket, string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if path, err := exec.LookPath("ss"); err == nil {
		// Primary: TCP+UDP, listening, numeric, processes, no header.
		// Requesting two socket families makes ss emit the Netid column.
		if out, err := exec.CommandContext(cmdCtx, path, "-tulnpH").Output(); err == nil && len(out) > 0 {
			// protoTCP is only a fallback for the single-family layout; with
			// -tu every row carries its own Netid, so it is never consulted.
			if sockets := parseSSOutput(string(out), protoTCP); len(sockets) > 0 {
				return sockets, "ss", nil
			}
		}

		// Fallback within ss: TCP-only. With a single family requested, ss
		// OMITS the Netid column and the row starts at State — hence the
		// explicit protocol argument.
		if out, err := exec.CommandContext(cmdCtx, path, "-tlnpH").Output(); err == nil && len(out) > 0 {
			if sockets := parseSSOutput(string(out), protoTCP); len(sockets) > 0 {
				return sockets, "ss-tcp", nil
			}
		}
	}

	// Last-resort fallback: netstat. Keep argument set conservative.
	if path, err := exec.LookPath("netstat"); err == nil {
		if out, err := exec.CommandContext(cmdCtx, path, "-tulnp").Output(); err == nil && len(out) > 0 {
			if sockets := parseNetstatOutput(string(out)); len(sockets) > 0 {
				return sockets, "netstat", nil
			}
		}
	}

	return nil, "", fmt.Errorf("neither ss nor netstat produced usable listening-socket output")
}

// ssStates is the set of connection-state tokens `ss` can print in its State
// column. Used purely for layout detection — to tell a State-first row from a
// Netid-first row — not for filtering.
var ssStates = map[string]struct{}{
	"LISTEN": {}, "UNCONN": {}, "ESTAB": {}, "SYN-SENT": {}, "SYN-RECV": {},
	"FIN-WAIT-1": {}, "FIN-WAIT-2": {}, "TIME-WAIT": {}, "CLOSE-WAIT": {},
	"LAST-ACK": {}, "CLOSING": {}, "CLOSED": {}, "UNKNOWN": {},
}

// normalizeProto maps a `ss`/`netstat` protocol token to the canonical
// "tcp"/"udp" values the platform contract expects. The v6 variants
// (tcp6/udp6, printed by netstat) collapse onto their base protocol — the
// address family is already evident from the bind address.
func normalizeProto(tok string) (string, bool) {
	switch strings.ToLower(tok) {
	case "tcp", "tcp4", "tcp6":
		return protoTCP, true
	case "udp", "udp4", "udp6":
		return protoUDP, true
	}
	return "", false
}

// parseSSOutput parses the headerless output of `ss`. Two column layouts exist
// and the difference is load-bearing:
//
// Netid-first — emitted when MORE THAN ONE socket family is requested
// (`ss -tulnpH`, i.e. -t and -u together):
//
//	tcp  LISTEN  0  4096  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
//	 0     1     2   3        4            5                  6
//
// State-first — emitted when a SINGLE family is requested (`ss -tlnpH`). ss
// drops the Netid column entirely because the protocol is implied by the flag:
//
//	LISTEN  0  4096  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
//	   0    1   2         3           4                  5
//
// defaultProto supplies the protocol for the State-first layout, where the row
// itself does not carry one. It is ignored for Netid-first rows.
//
// On a non-root agent the trailing users:(...) field is typically absent, so
// process_name and pid will be empty/zero — that's intentional.
func parseSSOutput(output string, defaultProto string) []listeningSocket {
	var sockets []listeningSocket

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Some `ss` builds still emit a header even with -H. Skip if so.
		if strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Layout detection, in order of specificity: a leading protocol token
		// means Netid-first; a leading state token means State-first.
		var (
			proto              string
			stateCol, localCol int
			usersCol           int
		)
		if p, ok := normalizeProto(fields[0]); ok {
			proto, stateCol, localCol, usersCol = p, 1, 4, 6
		} else if _, isState := ssStates[strings.ToUpper(fields[0])]; isState {
			proto, stateCol, localCol, usersCol = defaultProto, 0, 3, 5
		} else {
			// Unrecognized row (stray header, wrapped line, future format).
			continue
		}

		if localCol >= len(fields) || stateCol >= len(fields) {
			continue
		}

		// TCP listening sockets are state LISTEN. UDP has no listening state
		// (`ss` reports UNCONN), and -l already restricts the result set, so
		// UDP rows are accepted regardless of state.
		if proto == protoTCP && strings.ToUpper(fields[stateCol]) != "LISTEN" {
			continue
		}

		bindAddr, port, ok := splitHostPort(fields[localCol])
		if !ok {
			continue
		}

		// Process info, when present, is everything from the users column on,
		// rejoined — `users:(("name",pid=...,fd=...))` can contain spaces.
		processName, pid := "", 0
		if len(fields) > usersCol {
			processName, pid = parseSSUsersField(strings.Join(fields[usersCol:], " "))
		}

		sockets = append(sockets, listeningSocket{
			Proto:       proto,
			Port:        port,
			BindAddr:    bindAddr,
			ProcessName: processName,
			PID:         pid,
		})
	}

	return sockets
}

// parseSSUsersField parses a single ss `users:(...)` field into the first
// process name + pid. Real-world examples:
//
//	users:(("sshd",pid=1234,fd=3))
//	users:(("postgres",pid=987,fd=5),("postgres",pid=988,fd=6))
//
// On non-root agents the field will simply be missing (we never call this).
func parseSSUsersField(s string) (string, int) {
	idx := strings.Index(s, "users:((")
	if idx < 0 {
		return "", 0
	}
	s = s[idx+len("users:(("):]

	// Process name is the first quoted token.
	endQuote := strings.Index(s[1:], `"`)
	if !strings.HasPrefix(s, `"`) || endQuote < 0 {
		return "", 0
	}
	name := s[1 : 1+endQuote]
	rest := s[1+endQuote+1:]

	// PID lives after `pid=`.
	pidIdx := strings.Index(rest, "pid=")
	if pidIdx < 0 {
		return name, 0
	}
	pidStr := rest[pidIdx+len("pid="):]
	end := strings.IndexAny(pidStr, ",)")
	if end > 0 {
		pidStr = pidStr[:end]
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
	if err != nil {
		return name, 0
	}
	return name, pid
}

// parseNetstatOutput parses `netstat -tulnp` output. Header lines are
// skipped; the format is:
//
//	tcp  0  0  0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd
func parseNetstatOutput(output string) []listeningSocket {
	var sockets []listeningSocket

	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Proto") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto, ok := normalizeProto(fields[0])
		if !ok {
			continue
		}

		localCol := 3
		if localCol >= len(fields) {
			continue
		}
		bindAddr, port, valid := splitHostPort(fields[localCol])
		if !valid {
			continue
		}

		// For TCP, State should be LISTEN (column 5). UDP has no state.
		if proto == protoTCP {
			if len(fields) < 6 || strings.ToUpper(fields[5]) != "LISTEN" {
				continue
			}
		}

		// Process info: last column is pid/name (or `-` when redacted).
		processName, pid := "", 0
		if last := fields[len(fields)-1]; last != "-" {
			if slash := strings.IndexByte(last, '/'); slash > 0 {
				if p, err := strconv.Atoi(last[:slash]); err == nil {
					pid = p
				}
				processName = last[slash+1:]
			}
		}

		sockets = append(sockets, listeningSocket{
			Proto:       proto,
			Port:        port,
			BindAddr:    bindAddr,
			ProcessName: processName,
			PID:         pid,
		})
	}

	return sockets
}

// splitHostPort separates the bind address from the port in `ss`/`netstat`
// local-address output. Inputs include:
//
//	0.0.0.0:22
//	[::]:22
//	*:22
//	127.0.0.1:5432
func splitHostPort(s string) (string, int, bool) {
	// IPv6 form: [addr]:port
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || end+2 >= len(s) || s[end+1] != ':' {
			return "", 0, false
		}
		addr := s[1:end]
		port, err := strconv.Atoi(s[end+2:])
		if err != nil {
			return "", 0, false
		}
		return addr, port, true
	}

	// IPv4 / wildcard form: addr:port
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return "", 0, false
	}
	addr := s[:idx]
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return addr, port, true
}
