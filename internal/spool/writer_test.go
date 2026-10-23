//go:build !windows

package spool

import (
	"os"
	"path/filepath"
	"testing"
)

func loginEvent(n string) Event {
	return Event{
		V:          1,
		Type:       "ssh.login",
		Severity:   "info",
		Title:      "alice logged in over SSH from 203.0.113.7",
		OccurredAt: "2026-10-18T11:59:00Z",
		DedupeKey:  "auth:" + n,
		Labels:     map[string]string{"user": "alice", "source_ip": "203.0.113.7"},
	}
}

func TestWriteEventsRoundTrip(t *testing.T) {
	dir, r, _ := newSpool(t)
	want := []Event{loginEvent("1"), loginEvent("2")}
	if err := WriteEvents(dir, "agent-auth-1", want); err != nil {
		t.Fatal(err)
	}
	got := eventsOf(t, r.Next(16, 1<<20))
	if len(got) != 2 || got[0].DedupeKey != "auth:1" || got[1].DedupeKey != "auth:2" || got[0].Labels["user"] != "alice" {
		t.Fatalf("read back %+v", got)
	}
}

func TestWriteEventsRejectsInvalid(t *testing.T) {
	dir, _, _ := newSpool(t)
	bad := loginEvent("1")
	bad.Type = "Login"
	if err := WriteEvents(dir, "agent-auth-1", []Event{loginEvent("0"), bad}); err == nil {
		t.Fatal("an event breaking the contract was written")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "events"))
	if len(entries) != 0 {
		t.Fatalf("files left behind: %v", entries)
	}
}

func TestWriteEventsLeavesNoTmp(t *testing.T) {
	dir, _, _ := newSpool(t)
	if err := WriteEvents(dir, "agent-auth-1", []Event{loginEvent("1")}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "events"))
	if len(entries) != 1 || entries[0].Name() != "agent-auth-1.jsonl" {
		t.Fatalf("events/ holds %v, want only agent-auth-1.jsonl", entries)
	}
}

func TestWriteEventsCreatesEventsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvents(dir, "agent-auth-1", []Event{loginEvent("1")}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "events"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("events dir: %v %v", fi, err)
	}
}

func TestWriteEventsNothingToWrite(t *testing.T) {
	dir, _, _ := newSpool(t)
	if err := WriteEvents(dir, "agent-auth-1", nil); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "events"))
	if len(entries) != 0 {
		t.Fatalf("wrote a file for no events: %v", entries)
	}
}
