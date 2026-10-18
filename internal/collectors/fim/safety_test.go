package fim

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A walk cut short by its context must not be diffed: every file after the
// cut-off would otherwise be reported deleted.
func TestCancelledWalkIsDiscarded(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "w")
	os.MkdirAll(watched, 0o755)
	for _, n := range []string{"a", "b", "c"} {
		os.WriteFile(filepath.Join(watched, n), []byte(n), 0o644)
	}
	c := NewCollector("host", WithManifestPath(filepath.Join(dir, "state", "m")), WithInterval(time.Nanosecond))
	c.roots = []string{watched}
	c.Collect(context.Background())
	drain(c)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Collect(ctx)
	for _, s := range c.Snapshots() {
		for _, ch := range s.Payload["changes"].([]Change) {
			if ch.Change == ChangeDeleted {
				t.Fatalf("cancelled walk reported %s deleted", ch.Path)
			}
		}
	}
}

// A single-file root is watched through its parent directory; siblings in
// that directory are not in scope and must not be reported.
func TestRealtimeIgnoresSiblingsOfFileRoot(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	os.MkdirAll(etc, 0o755)
	passwd := filepath.Join(etc, "passwd")
	os.WriteFile(passwd, []byte("root"), 0o644)

	c := NewCollector("host", WithManifestPath(filepath.Join(dir, "state", "m")),
		WithRealtime(true), WithInterval(time.Hour))
	c.roots = []string{passwd}
	c.Collect(context.Background())
	drain(c)
	defer c.Close()

	os.WriteFile(filepath.Join(etc, "resolv.conf"), []byte("nameserver"), 0o644)
	time.Sleep(coalesceWindow + 300*time.Millisecond)
	c.Collect(context.Background())
	for _, s := range c.Snapshots() {
		for _, ch := range s.Payload["changes"].([]Change) {
			if ch.Path != passwd {
				t.Fatalf("out-of-scope path reported: %+v", ch)
			}
		}
	}
}

// A change must be re-offered until the post carrying it is acknowledged.
func TestChangesSurviveUnackedSend(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "w")
	os.MkdirAll(watched, 0o755)
	f := filepath.Join(watched, "f")
	os.WriteFile(f, []byte("v1"), 0o644)
	c := NewCollector("host", WithManifestPath(filepath.Join(dir, "state", "m")), WithInterval(time.Nanosecond))
	c.roots = []string{watched}
	c.Collect(context.Background())
	drain(c)

	os.WriteFile(f, []byte("v2"), 0o644)
	c.Collect(context.Background())
	if s := c.Snapshots(); len(s) != 1 || len(s[0].Payload["changes"].([]Change)) != 1 {
		t.Fatalf("expected the modification, got %+v", s)
	}
	// The post failed (no ack). The next cycle must still carry the change.
	c.Collect(context.Background())
	if s := c.Snapshots(); len(s) != 1 || len(s[0].Payload["changes"].([]Change)) != 1 {
		t.Fatalf("unacknowledged change was lost: %+v", s)
	}

	// An agent restart before the ack must not lose it either.
	c2 := NewCollector("host", WithManifestPath(filepath.Join(dir, "state", "m")), WithInterval(time.Nanosecond))
	c2.roots = []string{watched}
	c2.Collect(context.Background())
	s := c2.Snapshots()
	if len(s) != 1 || len(s[0].Payload["changes"].([]Change)) != 1 {
		t.Fatalf("unacknowledged change lost across restart: %+v", s)
	}

	// Once acknowledged, it is gone.
	c2.AckSnapshots()
	c2.Collect(context.Background())
	if s := c2.Snapshots(); len(s) != 0 {
		if n := len(s[0].Payload["changes"].([]Change)); n != 0 {
			t.Fatalf("acknowledged change re-sent: %+v", s)
		}
	}
}

// A size change with an identical (prefix) hash is still a modification.
func TestSizeChangeIsModification(t *testing.T) {
	base := map[string]Entry{"/big": {Path: "/big", Hash: "sha256:x", Mode: "0644", Size: 200 << 20}}
	cur := map[string]Entry{"/big": {Path: "/big", Hash: "sha256:x", Mode: "0644", Size: 300 << 20}}
	if cs := diff(base, cur, coversAll); len(cs) != 1 || cs[0].Change != ChangeModified {
		t.Fatalf("size change not reported: %+v", cs)
	}
}

// uid/gid 0 is real data (root) and must be serialized, not omitted.
func TestRootOwnerSerialized(t *testing.T) {
	base := map[string]Entry{}
	cur := map[string]Entry{"/x": {Path: "/x", Hash: "sha256:1", Mode: "0644", UID: ptr(uint32(0)), GID: ptr(uint32(0))}}
	b, _ := json.Marshal(diff(base, cur, coversAll))
	if !strings.Contains(string(b), `"uid":0`) {
		t.Fatalf("uid 0 dropped: %s", b)
	}
}

// An unreadable file is not a content modification.
func TestUnreadableIsNotModified(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-000 files")
	}
	dir := t.TempDir()
	watched := filepath.Join(dir, "w")
	os.MkdirAll(watched, 0o755)
	f := filepath.Join(watched, "f")
	os.WriteFile(f, []byte("v1"), 0o644)
	c := NewCollector("host", WithManifestPath(filepath.Join(dir, "state", "m")), WithInterval(time.Nanosecond))
	c.roots = []string{watched}
	c.Collect(context.Background())
	drain(c)
	os.Chmod(f, 0o000)
	defer os.Chmod(f, 0o644)
	c.Collect(context.Background())
	for _, s := range c.Snapshots() {
		for _, ch := range s.Payload["changes"].([]Change) {
			if ch.Change == ChangeModified {
				t.Fatalf("unreadable file reported modified: %+v", ch)
			}
		}
	}
}

// A change detected while a snapshot is in flight is not cleared by that
// snapshot's ack.
func TestAckClearsOnlyWhatWasSent(t *testing.T) {
	c := NewCollector("host", WithManifestPath(filepath.Join(t.TempDir(), "state", "m")))
	c.report = &reportState{evaluatedAt: time.Now()}
	c.loaded = true
	c.enqueue([]Change{{Path: "/a", Change: ChangeModified}})
	if s := c.Snapshots(); len(s[0].Payload["changes"].([]Change)) != 1 {
		t.Fatal("expected /a")
	}
	c.enqueue([]Change{{Path: "/b", Change: ChangeModified}})
	c.AckSnapshots()
	s := c.Snapshots()
	cs := s[0].Payload["changes"].([]Change)
	if len(cs) != 1 || cs[0].Path != "/b" {
		t.Fatalf("expected only /b to remain, got %+v", cs)
	}
}

// The queue is bounded; overflow is counted, not silently lost.
func TestPendingChangesCapped(t *testing.T) {
	c := NewCollector("host", WithManifestPath(filepath.Join(t.TempDir(), "state", "m")))
	c.report = &reportState{evaluatedAt: time.Now()}
	var many []Change
	for i := 0; i < maxPendingChanges+25; i++ {
		many = append(many, Change{Path: "/f" + strconv.Itoa(i), Change: ChangeCreated})
	}
	c.enqueue(many)
	p := c.Snapshots()[0].Payload
	if n := len(p["changes"].([]Change)); n != maxPendingChanges {
		t.Errorf("changes = %d, want %d", n, maxPendingChanges)
	}
	if p["changes_dropped"] != 25 {
		t.Errorf("changes_dropped = %v, want 25", p["changes_dropped"])
	}
}

// A walk that overruns its own budget is discarded and the baseline kept.
func TestWalkOverBudgetDiscarded(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "w")
	os.MkdirAll(watched, 0o755)
	os.WriteFile(filepath.Join(watched, "a"), []byte("a"), 0o644)
	c := NewCollector("host", WithManifestPath(filepath.Join(dir, "state", "m")), WithInterval(time.Nanosecond))
	c.roots = []string{watched}
	c.Collect(context.Background())
	drain(c)
	id := c.manifestID

	c.walkTimeout = time.Nanosecond
	c.Collect(context.Background())
	if s := c.Snapshots(); len(s) != 0 {
		t.Fatalf("over-budget walk was reported: %+v", s)
	}
	if c.manifestID != id || len(c.entries) != 1 {
		t.Fatal("over-budget walk replaced the baseline")
	}
}

// A capped walk carries unreached baseline files instead of deleting them,
// but still reports deletions where it did look.
func TestTruncatedWalkOnlyDeletesWhereItLooked(t *testing.T) {
	dir := t.TempDir()
	seen := filepath.Join(dir, "seen")
	unseen := filepath.Join(dir, "unseen")
	os.MkdirAll(seen, 0o755)
	os.MkdirAll(unseen, 0o755)
	base := map[string]Entry{
		filepath.Join(seen, "gone"):   {Path: filepath.Join(seen, "gone"), Hash: "sha256:1"},
		filepath.Join(unseen, "kept"): {Path: filepath.Join(unseen, "kept"), Hash: "sha256:2"},
	}
	res := &walkResult{
		entries:   map[string]Entry{},
		truncated: true,
		examined:  map[string]struct{}{seen: {}},
	}
	cs := diff(base, res.entries, res.covers)
	if len(cs) != 1 || cs[0].Path != filepath.Join(seen, "gone") || cs[0].Change != ChangeDeleted {
		t.Fatalf("expected only seen/gone deleted, got %+v", cs)
	}
	if _, ok := res.entries[filepath.Join(unseen, "kept")]; !ok {
		t.Fatal("unreached entry was not carried over")
	}
}

// A changed root set rebuilds with a stated reason instead of reporting a
// storm of creates and deletes.
func TestRootsChangeRebuildsWithReason(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	os.MkdirAll(a, 0o755)
	os.MkdirAll(b, 0o755)
	os.WriteFile(filepath.Join(a, "1"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(b, "2"), []byte("2"), 0o644)
	m := filepath.Join(dir, "state", "m")

	c := NewCollector("host", WithManifestPath(m))
	c.roots = []string{a}
	c.Collect(context.Background())
	drain(c)

	c2 := NewCollector("host", WithManifestPath(m))
	c2.roots = []string{a, b}
	c2.Collect(context.Background())
	p := drain(c2)[0].Payload
	if p["baseline_rebuilt"] != true || p["rebuild_reason"] != reasonRootsChanged {
		t.Fatalf("expected a roots_changed rebuild, got %+v", p)
	}
	if n := len(p["changes"].([]Change)); n != 0 {
		t.Fatalf("rebuild carried %d changes", n)
	}
}

// A manifest in a directory other accounts can write is not trusted.
func TestWritableManifestDirUntrusted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	m := filepath.Join(dir, "fim-manifest")
	if err := saveManifest(m, &Manifest{ID: "x"}); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o777)
	if _, _, err := loadManifest(m); !errors.Is(err, errManifestUntrusted) {
		t.Fatalf("world-writable manifest dir accepted: %v", err)
	}
	os.Chmod(dir, 0o700)
	os.Chmod(m, 0o666)
	if _, _, err := loadManifest(m); !errors.Is(err, errManifestUntrusted) {
		t.Fatalf("world-writable manifest accepted: %v", err)
	}
}

// Real-time re-checks and walks may overlap without racing on the baseline.
func TestRealtimeAndWalkSerialized(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "w")
	os.MkdirAll(watched, 0o755)
	f := filepath.Join(watched, "f")
	os.WriteFile(f, []byte("v1"), 0o644)
	c := NewCollector("host", WithManifestPath(filepath.Join(dir, "state", "m")),
		WithRealtime(true), WithInterval(time.Nanosecond))
	c.roots = []string{watched}
	defer c.Close()
	c.Collect(context.Background())
	drain(c)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			os.WriteFile(f, []byte("v"+strconv.Itoa(i)), 0o644)
			c.Collect(context.Background())
			c.realtimeDelta(context.Background())
			drain(c)
		}(i)
	}
	wg.Wait()
	if c.manifestID == "" {
		t.Fatal("manifest id lost")
	}
}
