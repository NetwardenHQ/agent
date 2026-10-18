//go:build !windows

package container

import (
	"context"
	"testing"
	"time"
)

func TestParsePercent(t *testing.T) {
	cases := map[string]float64{
		"18.18%": 18.18, "0.00%": 0, "100%": 100, " 4.5 % ": 4.5,
	}
	for in, want := range cases {
		if got, ok := parsePercent(in); !ok || got != want {
			t.Errorf("parsePercent(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	// Unreadable input is unknown, never a 0 that would graph as idle.
	for _, in := range []string{"", "--", "n/a", "abc%"} {
		if got, ok := parsePercent(in); ok {
			t.Errorf("parsePercent(%q) = %v, known; want unknown", in, got)
		}
	}
}

func TestParseSize(t *testing.T) {
	cases := map[string]uint64{
		"856.1kB": 856100,
		"33.45GB": 33450000000,
		"704B":    704,
		"0B":      0,
		"1kB":     1000,
		"1KiB":    1024,
		"2MiB":    2 * 1024 * 1024,
	}
	for in, want := range cases {
		if got, ok := parseSize(in); !ok || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	// Unreadable input is unknown, never a guess and never a 0.
	for _, in := range []string{"", "--", "lots", "12 ZB"} {
		if got, ok := parseSize(in); ok {
			t.Errorf("parseSize(%q) = %d, known; want unknown", in, got)
		}
	}
}

func TestParsePair(t *testing.T) {
	rx, tx, ok := parsePair("704B / 716B")
	if !ok || rx != 704 || tx != 716 {
		t.Errorf("net_io: got %d/%d %v, want 704/716", rx, tx, ok)
	}
	used, limit, ok := parsePair("856.1kB / 33.45GB")
	if !ok || used != 856100 || limit != 33450000000 {
		t.Errorf("mem_usage: got %d/%d %v", used, limit, ok)
	}
	r, w, ok := parsePair("0B / 0B")
	if !ok || r != 0 || w != 0 {
		t.Errorf("block_io zero case: got %d/%d %v", r, w, ok)
	}
	// A malformed or unknown pair is unknown as a whole.
	for _, in := range []string{"512B", "-- / --", "1kB / --"} {
		if a, b, ok := parsePair(in); ok {
			t.Errorf("parsePair(%q) = %d/%d, known; want unknown", in, a, b)
		}
	}
}

// A "--" stat row (container just started, cgroup not readable) yields no
// figures at all rather than zeros.
func TestPodmanStatsFromEntry_UnknownFieldsOmitted(t *testing.T) {
	s := podmanStatsFromEntry("c1", podmanStatsEntry{
		CPUPercent: "--", MemUsage: "-- / --", NetIO: "1kB / 2kB", BlockIO: "--",
	})
	if s.CPUKnown || s.MemoryKnown || s.DiskKnown {
		t.Errorf("unknown fields reported known: %+v", s)
	}
	if !s.NetworkKnown || s.NetworkRxBytes != 1000 || s.NetworkTxBytes != 2000 {
		t.Errorf("network lost: %+v", s)
	}
}

// `podman ps --format json` reports ImageID as bare hex; the socket clients
// report "sha256:<hex>".
func TestPodmanCLIImageIDNormalized(t *testing.T) {
	hex := "8f4b6b1a3c9d0e2f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	if got := normalizeImageID(hex); got != "sha256:"+hex {
		t.Errorf("normalizeImageID(bare) = %q", got)
	}
	if got := normalizeImageID("sha256:" + hex); got != "sha256:"+hex {
		t.Errorf("normalizeImageID(prefixed) = %q", got)
	}
	if got := normalizeImageID(""); got != "" {
		t.Errorf("normalizeImageID(empty) = %q", got)
	}
}

// Live check against whatever Podman is on this machine. Skips where there is
// none, so it is safe in CI while still catching a format change locally.
func TestPodmanCLILive(t *testing.T) {
	c := NewPodmanCLIClient()
	if !c.IsAvailable() {
		t.Skip("podman not available on this host")
	}
	if c.Name() != "podman" {
		t.Fatalf("Name() = %q", c.Name())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	list, err := c.ListContainers(ctx)
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	for _, ct := range list {
		if ct.ID == "" {
			t.Error("container returned with an empty ID")
		}
	}
	t.Logf("listed %d container(s) via the CLI", len(list))
}
