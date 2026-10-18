package fim

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// End-to-end real-time: establish a baseline, then modify a file and confirm
// the fsnotify layer surfaces it as a realtime delta on the next collect,
// without waiting out the hourly walk.
func TestRealtime_DetectsChangeBetweenWalks(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "w")
	os.MkdirAll(watched, 0o755)
	target := filepath.Join(watched, "app")
	os.WriteFile(target, []byte("v1"), 0o755)

	c := NewCollector("host",
		WithManifestPath(filepath.Join(dir, "state", "manifest")),
		WithRealtime(true),
		WithInterval(time.Hour), // so the second Collect is throttled -> realtime path
		WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
	)
	c.roots = []string{watched}

	// Cycle 1: full walk establishes baseline and starts the watcher.
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	drain(c)

	if c.watcher == nil {
		t.Fatal("watcher should have started")
	}
	defer c.Close()

	if err := os.WriteFile(target, []byte("v2-tampered"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Give fsnotify and the coalesce window time to register the event.
	deadline := time.Now().Add(5 * time.Second)
	var changes []Change
	for time.Now().Before(deadline) {
		time.Sleep(coalesceWindow + 100*time.Millisecond)
		if _, err := c.Collect(context.Background()); err != nil {
			t.Fatal(err)
		}
		snaps := drain(c)
		if len(snaps) == 1 {
			if cs, ok := snaps[0].Payload["changes"].([]Change); ok && len(cs) > 0 {
				changes = cs
				break
			}
		}
	}

	if len(changes) == 0 {
		t.Fatal("real-time layer did not surface the change within the deadline")
	}
	found := false
	for _, ch := range changes {
		if ch.Path == target && ch.Change == ChangeModified && ch.Detected == "realtime" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a realtime modified change for %s, got %+v", target, changes)
	}
}

func TestWatcher_CoalesceHoldsRecentEvents(t *testing.T) {
	w := &watcher{dirty: map[string]time.Time{}, stop: make(chan struct{})}
	// A just-recorded event is within the window: not yet ready.
	w.dirty["/x"] = time.Now()
	if got := w.drainDirty(); len(got) != 0 {
		t.Errorf("event within coalesce window should not drain yet, got %v", got)
	}
	// An old event drains.
	w.dirty["/y"] = time.Now().Add(-2 * coalesceWindow)
	if got := w.drainDirty(); len(got) != 1 || got[0] != "/y" {
		t.Errorf("aged event should drain, got %v", got)
	}
}
