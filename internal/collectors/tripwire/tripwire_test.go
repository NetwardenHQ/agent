package tripwire

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

type got map[string][]metrics.Metric

func collect(t *testing.T, c *Collector) got {
	t.Helper()
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	out := got{}
	for _, m := range ms {
		out[m.Name] = append(out[m.Name], m)
	}
	return out
}

func (g got) one(t *testing.T, name string, want map[string]string) float64 {
	t.Helper()
	var found []metrics.Metric
	for _, m := range g[name] {
		ok := true
		for k, v := range want {
			if m.Labels[k] != v {
				ok = false
			}
		}
		if ok {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s %v: want one series, got %d (%v)", name, want, len(found), g[name])
	}
	return found[0].Value
}

type env struct {
	root  string
	clock time.Time
}

func (e *env) path(parts ...string) string {
	return filepath.Join(append([]string{e.root}, parts...)...)
}

func (e *env) write(t *testing.T, rel, text string) string {
	t.Helper()
	p := e.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func newEnv(t *testing.T) *env { return &env{root: t.TempDir(), clock: t0} }

func (e *env) collector(opts ...Option) *Collector {
	base := []Option{
		WithStatePath(e.path("state", "tripwire.json")),
		withClock(func() time.Time { return e.clock }),
		withVolumes(e.path("volume*")),
		withSyncWalks(),
	}
	return NewCollector("host", append(base, opts...)...)
}

func TestCanaryIntactThenModified(t *testing.T) {
	e := newEnv(t)
	p := e.write(t, "volume1/homes/alice/Documents/Passwords.xls", "fake accounts")
	c := e.collector(WithCanaries([]string{p}))
	g := collect(t, c)
	if v := g.one(t, "tripwire_canary_intact", map[string]string{"canary": p, "state": "intact"}); v != 1 {
		t.Errorf("intact = %v", v)
	}
	for name, want := range map[string]float64{"tripwire_canaries_watched": 1, "tripwire_canaries_tampered": 0, "tripwire_canaries_unreadable": 0} {
		if v := g.one(t, name, nil); v != want {
			t.Errorf("%s = %v, want %v", name, v, want)
		}
	}

	e.write(t, "volume1/homes/alice/Documents/Passwords.xls", "ENCRYPTED GARBAGE")
	g = collect(t, c)
	if v := g.one(t, "tripwire_canary_intact", map[string]string{"canary": p, "state": "modified"}); v != 0 {
		t.Errorf("modified canary reported intact")
	}
	if v := g.one(t, "tripwire_canaries_tampered", nil); v != 1 {
		t.Errorf("tampered = %v", v)
	}

	// Still tampered after a restart: the baseline survives.
	g = collect(t, e.collector(WithCanaries([]string{p})))
	if v := g.one(t, "tripwire_canaries_tampered", nil); v != 1 {
		t.Errorf("a restart forgot the tampering")
	}
}

func TestCanaryMissingAndUnreadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads everything")
	}
	e := newEnv(t)
	a := e.write(t, "a/canary-a.txt", "a")
	b := e.write(t, "b/canary-b.txt", "b")
	c := e.collector(WithCanaries([]string{a, b}))
	collect(t, c)

	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(b, 0o000); err != nil {
		t.Fatal(err)
	}
	g := collect(t, c)
	if v := g.one(t, "tripwire_canary_intact", map[string]string{"canary": a, "state": "missing"}); v != 0 {
		t.Errorf("missing canary intact")
	}
	if v := g.one(t, "tripwire_canary_intact", map[string]string{"canary": b, "state": "unreadable"}); v != 0 {
		t.Errorf("unreadable canary intact")
	}
	if v := g.one(t, "tripwire_canaries_tampered", nil); v != 1 {
		t.Errorf("tampered = %v", v)
	}
	// Unreadable is its own count: usually permissions, which needs a different fix.
	if v := g.one(t, "tripwire_canaries_unreadable", nil); v != 1 {
		t.Errorf("unreadable = %v", v)
	}
}

func TestPinnedHash(t *testing.T) {
	e := newEnv(t)
	p := e.write(t, "x/Passwords.xls", "the real canary")
	// sha256 of "the real canary" is not this; the pin wins over a fresh baseline.
	c := e.collector(WithCanaries([]string{p + "@sha256:" + "00000000000000000000000000000000000000000000000000000000000000aa"}))
	g := collect(t, c)
	if v := g.one(t, "tripwire_canaries_tampered", nil); v != 1 {
		t.Errorf("a canary not matching its pinned hash was accepted")
	}
}

func TestMissingFromTheStart(t *testing.T) {
	e := newEnv(t)
	p := e.path("never/there.xls")
	g := collect(t, e.collector(WithCanaries([]string{p})))
	if v := g.one(t, "tripwire_canary_intact", map[string]string{"canary": p, "state": "missing"}); v != 0 {
		t.Errorf("a canary that never existed was reported intact")
	}
}

func TestCanaryInNewestSnapshot(t *testing.T) {
	e := newEnv(t)
	p := e.write(t, "volume1/homes/alice/Documents/Passwords.xls", "fake accounts")
	c := e.collector(WithCanaries([]string{p}))
	collect(t, c) // baseline at t0 (12:00 UTC)

	// A snapshot from before the canary existed is not judged.
	if err := os.MkdirAll(e.path("volume1/@sharesnap/homes/GMT+00-2026.11.13-11.00.00"), 0o755); err != nil {
		t.Fatal(err)
	}
	g := collect(t, c)
	if len(g["tripwire_canary_snapshot_intact"]) != 0 {
		t.Errorf("a snapshot older than the canary was judged: %v", g["tripwire_canary_snapshot_intact"])
	}

	e.clock = t0.Add(time.Hour)
	e.write(t, "volume1/@sharesnap/homes/GMT+00-2026.11.13-12.30.00/alice/Documents/Passwords.xls", "fake accounts")
	g = collect(t, c)
	if v := g.one(t, "tripwire_canary_snapshot_intact", map[string]string{"canary": p, "snapshot": "GMT+00-2026.11.13-12.30.00", "state": "intact"}); v != 1 {
		t.Errorf("snapshot copy not intact")
	}
	if v := g.one(t, "tripwire_canary_snapshots_bad", nil); v != 0 {
		t.Errorf("snapshots_bad = %v", v)
	}

	// The next snapshot was taken after encryption.
	e.write(t, "volume1/@sharesnap/homes/GMT+00-2026.11.13-13.00.00/alice/Documents/Passwords.xls", "ENCRYPTED")
	g = collect(t, c)
	if v := g.one(t, "tripwire_canary_snapshots_bad", nil); v != 1 {
		t.Errorf("an encrypted snapshot copy was accepted")
	}
}

func TestNothingConfiguredIsDisabled(t *testing.T) {
	if (newEnv(t).collector()).Enabled() {
		t.Error("enabled with nothing to watch")
	}
}

// A canary pinned to its real hash but already altered when the agent first
// saw it: the live file is tampered, and the snapshot copy (the real one) is
// intact. Only the hash is compared; the altered file's size is never
// learned as the baseline.
func TestPinnedCanaryAlteredBeforeFirstSight(t *testing.T) {
	e := newEnv(t)
	real := "the real canary contents"
	p := e.write(t, "volume1/homes/alice/Documents/Passwords.xls", "ENCRYPTED, AND LONGER THAN THE ORIGINAL")
	sum := sha256Hex(real)
	c := e.collector(WithCanaries([]string{p + "@sha256:" + sum}))
	g := collect(t, c)
	if v := g.one(t, "tripwire_canaries_tampered", nil); v != 1 {
		t.Fatalf("tampered = %v", v)
	}
	e.clock = t0.Add(time.Hour)
	e.write(t, "volume1/@sharesnap/homes/GMT+00-2026.11.13-12.30.00/alice/Documents/Passwords.xls", real)
	g = collect(t, c)
	if v := g.one(t, "tripwire_canary_snapshots_bad", nil); v != 0 {
		t.Errorf("the intact snapshot copy was judged against the tampered file")
	}
}

// Adding a pin later makes the pin the expectation everywhere.
func TestPinAddedLaterWins(t *testing.T) {
	e := newEnv(t)
	p := e.write(t, "x/Passwords.xls", "learned first")
	collect(t, e.collector(WithCanaries([]string{p})))
	g := collect(t, e.collector(WithCanaries([]string{p + "@sha256:" + sha256Hex("something else")})))
	if v := g.one(t, "tripwire_canaries_tampered", nil); v != 1 {
		t.Errorf("a canary not matching its new pin passed on the learned baseline")
	}
}
