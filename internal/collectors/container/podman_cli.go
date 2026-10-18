//go:build !windows

package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// PodmanCLIClient talks to Podman through its command line instead of its
// REST API.
//
// Podman does not run an API socket by default. On Debian and Ubuntu
// `podman.socket` ships disabled, so a host can run containers while
// /run/podman/podman.sock does not exist, and the socket client would report
// no containers at all. Docker's daemon always owns a socket, so this fallback
// is Podman-only and is tried after the socket clients.
type PodmanCLIClient struct {
	binary  string
	timeout time.Duration
}

func NewPodmanCLIClient() *PodmanCLIClient {
	return &PodmanCLIClient{binary: "podman", timeout: 15 * time.Second}
}

func (p *PodmanCLIClient) Name() string { return "podman" }

// IsAvailable reports whether the podman binary exists and answers, so a
// broken or unconfigured Podman falls through to "no runtime" rather than
// erroring every cycle.
func (p *PodmanCLIClient) IsAvailable() bool {
	if _, err := exec.LookPath(p.binary); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	return exec.CommandContext(ctx, p.binary, "info", "--format", "{{.Host.Arch}}").Run() == nil
}

// podmanPSEntry is the subset of `podman ps --format json` that is read.
type podmanPSEntry struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
	Created int64             `json:"Created"`
}

func (p *PodmanCLIClient) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, p.binary, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("podman %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// ListContainers returns every container, running or not, to match what the
// socket client reports with all=true.
func (p *PodmanCLIClient) ListContainers(ctx context.Context) ([]Container, error) {
	out, err := p.run(ctx, "ps", "--all", "--format", "json")
	if err != nil {
		return nil, err
	}

	var entries []podmanPSEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("parse podman ps output: %w", err)
	}

	containers := make([]Container, 0, len(entries))
	for _, e := range entries {
		name := ""
		if len(e.Names) > 0 {
			name = e.Names[0]
		}
		containers = append(containers, Container{
			ID:      e.ID,
			Name:    name,
			Image:   e.Image,
			ImageID: normalizeImageID(e.ImageID), // bare hex here
			// Podman and the socket client use the same state vocabulary
			// ("running", "exited", "paused").
			Status:  strings.ToLower(e.State),
			Labels:  e.Labels,
			Created: time.Unix(e.Created, 0),
		})
	}
	return containers, nil
}

// podmanStatsEntry mirrors `podman stats --no-stream --format json`.
//
// Verified against Podman 5.7: keys are snake_case and sizes are
// human-readable strings, not byte counts. A row looks like:
//
//	{"id":"d3c67951d33f","name":"probe","cpu_percent":"18.18%",
//	 "mem_usage":"856.1kB / 33.45GB","net_io":"704B / 716B",
//	 "block_io":"0B / 0B","pids":"1"}
type podmanStatsEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CPUPercent string `json:"cpu_percent"`
	MemUsage   string `json:"mem_usage"` // "used / limit"
	NetIO      string `json:"net_io"`    // "rx / tx"
	BlockIO    string `json:"block_io"`  // "read / write"
}

// parsePercent turns "18.18%" into 18.18. Anything unparseable (podman
// prints "--" when it cannot read a cgroup) is unknown rather than 0.
func parsePercent(s string) (float64, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// sizeUnits are what Podman emits, which is SI (kB = 1000) with the IEC
// spellings also accepted because other versions have used them.
var sizeUnits = map[string]float64{
	"b":  1,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
}

// parseSize turns "856.1kB" into bytes. Anything it cannot read is unknown,
// for the same reason as parsePercent.
func parseSize(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "--" {
		return 0, false
	}
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	if i == 0 {
		return 0, false
	}
	value, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, false
	}
	unit := strings.ToLower(strings.TrimSpace(s[i:]))
	if unit == "" {
		return uint64(value), true
	}
	mult, ok := sizeUnits[unit]
	if !ok {
		return 0, false
	}
	return uint64(value * mult), true
}

// parsePair splits Podman's "a / b" fields. The pair is known only when both
// halves are.
func parsePair(s string) (uint64, uint64, bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, okA := parseSize(parts[0])
	b, okB := parseSize(parts[1])
	if !okA || !okB {
		return 0, 0, false
	}
	return a, b, true
}

// podmanStatsFromEntry converts one `podman stats` row. cpu_percent is
// already on the docker/podman scale (100 = one core): podman divides the
// cgroup's CPU time by wall time, not by host CPU time.
func podmanStatsFromEntry(id string, e podmanStatsEntry) *ContainerStats {
	stats := &ContainerStats{ContainerID: id}
	stats.CPUPercent, stats.CPUKnown = parsePercent(e.CPUPercent)
	// The limit half of mem_usage is the host total unless a cgroup cap is
	// set, and the CLI does not say which, so no limit is reported.
	if used, _, ok := parsePair(e.MemUsage); ok {
		stats.MemoryUsage, stats.MemoryKnown = used, true
	}
	stats.NetworkRxBytes, stats.NetworkTxBytes, stats.NetworkKnown = parsePair(e.NetIO)
	stats.DiskReadBytes, stats.DiskWriteBytes, stats.DiskKnown = parsePair(e.BlockIO)
	return stats
}

// GetContainerStats reads one container's resource usage.
//
// Without --no-stream `podman stats` streams forever and the call would block
// until its context expired.
func (p *PodmanCLIClient) GetContainerStats(ctx context.Context, id string) (*ContainerStats, error) {
	out, err := p.run(ctx, "stats", "--no-stream", "--format", "json", id)
	if err != nil {
		return nil, err
	}

	var entries []podmanStatsEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("parse podman stats output: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no stats returned for container %s", id)
	}

	return podmanStatsFromEntry(id, entries[0]), nil
}

// Close is a no-op: each call is its own short-lived process.
func (p *PodmanCLIClient) Close() error { return nil }

// newPodmanCLIClientIfSupported returns the CLI fallback on platforms where
// it applies. The build-tagged constructor keeps build tags out of the
// detector.
func newPodmanCLIClientIfSupported() RuntimeClient { return NewPodmanCLIClient() }
