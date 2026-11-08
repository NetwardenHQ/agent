//go:build !windows

package spool

import (
	"os"
	"path/filepath"
	"testing"
)

func oneEvent() []Event {
	return []Event{{V: 1, Type: "web.probe", Severity: "info", Title: "t", OccurredAt: "2026-10-23T14:10:00Z", DedupeKey: "probe:203.0.113.9:1"}}
}

// worldWritable makes a directory the way the kubelet makes an emptyDir.
func worldWritable(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOwnVolumeTrustsTheAgentsOwnSpool(t *testing.T) {
	volume := worldWritable(t)
	dir := filepath.Join(volume, "agent")
	r := New(dir, WithOwnVolume(volume))
	if err := r.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvents(dir, "edge-1", oneEvent()); err != nil {
		t.Fatal(err)
	}
	if got := eventsOf(t, r.Next(10, 1<<20)); len(got) != 1 {
		t.Fatalf("%d events read from the agent's own spool", len(got))
	}
	// Without it the same spool is refused: the volume above it is
	// world-writable and not sticky.
	if got := eventsOf(t, New(dir, WithOwnerUID(os.Getuid())).Next(10, 1<<20)); len(got) != 0 {
		t.Fatalf("%d events read through a world-writable parent", len(got))
	}
}

func TestOwnVolumeStillChecksTheSpool(t *testing.T) {
	volume := worldWritable(t)
	dir := filepath.Join(volume, "agent")
	if err := os.MkdirAll(filepath.Join(dir, "events"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvents(dir, "edge-1", oneEvent()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if got := eventsOf(t, New(dir, WithOwnVolume(volume)).Next(10, 1<<20)); len(got) != 0 {
		t.Fatalf("%d events read from a group-writable spool", len(got))
	}
}

func TestOwnVolumeCoversOnlyItsVolume(t *testing.T) {
	volume := t.TempDir()
	elsewhere := worldWritable(t)
	dir := filepath.Join(elsewhere, "agent")
	r := New(dir, WithOwnVolume(volume))
	if err := r.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvents(dir, "edge-1", oneEvent()); err != nil {
		t.Fatal(err)
	}
	if got := eventsOf(t, r.Next(10, 1<<20)); len(got) != 0 {
		t.Fatalf("%d events read from outside the volume", len(got))
	}
}
