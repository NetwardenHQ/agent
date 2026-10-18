package fim

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// drain takes the staged snapshots and acknowledges them, as the agent does
// after a successful post.
func drain(c *Collector) []metrics.Snapshot {
	s := c.Snapshots()
	c.AckSnapshots()
	return s
}

// The core lifecycle: first walk establishes a baseline and reports no
// changes; a subsequent walk after a real modification reports exactly it.
func TestCollector_BaselineThenDetect(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "watched")
	os.MkdirAll(watched, 0o755)
	bin := filepath.Join(watched, "app")
	os.WriteFile(bin, []byte("v1"), 0o755)

	manifest := filepath.Join(dir, "state", "fim-manifest")
	c := NewCollector("host",
		WithManifestPath(manifest),
		WithRoots([]string{watched}),
		WithInterval(time.Nanosecond), // no throttle between the two Collects
	)
	c.roots = []string{watched} // test only: replace the default ruleset

	// --- cycle 1: establish baseline ---
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap1 := drain(c)
	if len(snap1) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snap1))
	}
	p1 := snap1[0].Payload
	if p1["baseline_rebuilt"] != true {
		t.Error("first cycle should report baseline_rebuilt=true")
	}
	if n := len(p1["changes"].([]Change)); n != 0 {
		t.Errorf("first cycle should report 0 changes, got %d", n)
	}
	if _, err := os.Stat(manifest); err != nil {
		t.Errorf("manifest should have been persisted: %v", err)
	}

	// --- modify the watched binary ---
	os.WriteFile(bin, []byte("v2-tampered"), 0o755)

	// --- cycle 2: detect the change ---
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap2 := drain(c)
	if len(snap2) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snap2))
	}
	p2 := snap2[0].Payload
	if p2["baseline_rebuilt"] != false {
		t.Error("second cycle should not be a rebuild")
	}
	changes := p2["changes"].([]Change)
	if len(changes) != 1 || changes[0].Path != bin || changes[0].Change != ChangeModified {
		t.Fatalf("expected one modified change for %s, got %+v", bin, changes)
	}
	if changes[0].Hash == changes[0].WasHash {
		t.Error("modified change should carry differing hashes")
	}
	if p1["digest"] == p2["digest"] {
		t.Error("roll-up digest should change when a watched file changes")
	}
}

// A wiped manifest is caught: the next cycle rebuilds (baseline_rebuilt=true)
// and mints a new manifest_id, which is the platform's tamper signal.
func TestCollector_WipedManifestRebuilds(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "w")
	os.MkdirAll(watched, 0o755)
	os.WriteFile(filepath.Join(watched, "f"), []byte("x"), 0o644)
	manifest := filepath.Join(dir, "state", "fim-manifest")

	c := NewCollector("host", WithManifestPath(manifest), WithInterval(time.Nanosecond))
	c.roots = []string{watched} // test only: replace the default ruleset

	c.Collect(context.Background())
	id1 := drain(c)[0].Payload["manifest_id"].(string)

	// Attacker wipes the baseline.
	os.Remove(manifest)

	c.Collect(context.Background())
	p := drain(c)[0].Payload
	if p["baseline_rebuilt"] != true {
		t.Error("a wiped manifest must force a rebuild")
	}
	if p["manifest_id"].(string) == id1 {
		t.Error("rebuild must mint a new manifest_id (the tamper signal)")
	}
}

func TestCollector_Throttles(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "w")
	os.MkdirAll(watched, 0o755)
	os.WriteFile(filepath.Join(watched, "f"), []byte("x"), 0o644)

	c := NewCollector("host",
		WithManifestPath(filepath.Join(dir, "state", "m")),
		WithRoots([]string{watched}),
		WithInterval(time.Hour), // long throttle
	)
	c.roots = []string{watched} // test only: replace the default ruleset
	c.Collect(context.Background())
	drain(c)
	// Second immediate collect is throttled: re-emits metrics, no new snapshot.
	c.Collect(context.Background())
	if snaps := drain(c); len(snaps) != 0 {
		t.Errorf("throttled cycle should stage no snapshot, got %d", len(snaps))
	}
}

func TestCollector_DisabledWithoutRoots(t *testing.T) {
	// No default roots + none configured -> nothing to watch.
	c := &Collector{roots: nil}
	if c.Enabled() {
		t.Error("collector with no roots should report disabled")
	}
}
