package agent

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readState(t *testing.T, p string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStateFileSchemaAndAtomicity(t *testing.T) {
	root := t.TempDir()
	spoolDir := filepath.Join(root, "spool")
	started := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	s := newStateFile(spoolDir, "3.0.0", started, slog.Default())
	p := filepath.Join(root, "state.json")
	if s.path != p {
		t.Fatalf("state lives next to the spool dir: %s", s.path)
	}

	s.Init(60 * time.Second)
	m := readState(t, p)
	if m["v"] != float64(1) || m["agent_version"] != "3.0.0" || m["started_at"] != "2026-10-18T12:00:00Z" || m["pid"] != float64(os.Getpid()) {
		t.Fatalf("%v", m)
	}
	sp := m["spool"].(map[string]any)
	if sp["supported"] != true || sp["version"] != float64(1) || sp["dir"] != spoolDir {
		t.Fatalf("%v", sp)
	}
	if _, has := m["last_post_ok_at"]; has {
		t.Fatal("no successful post yet: last_post_ok_at must be absent")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}

	t1 := started.Add(time.Minute)
	s.Update(attempt{At: t1, Status: 200, Interval: time.Minute, Sent: 7, Pending: 3})
	m = readState(t, p)
	if m["last_post_ok_at"] != "2026-10-18T12:01:00Z" || m["last_post_attempt_at"] != m["last_post_ok_at"] ||
		m["last_post_status"] != float64(200) || m["last_error"] != nil ||
		m["events_sent_total"] != float64(7) || m["events_pending"] != float64(3) || m["interval_seconds"] != float64(60) {
		t.Fatalf("%v", m)
	}

	// A failed attempt moves attempt time and error, keeps the last OK time.
	s.Update(attempt{At: t1.Add(time.Minute), Err: errors.New("request failed: boom"), Interval: time.Minute})
	m = readState(t, p)
	if m["last_post_ok_at"] != "2026-10-18T12:01:00Z" || m["last_post_attempt_at"] != "2026-10-18T12:02:00Z" ||
		m["last_error"] != "request failed: boom" || m["last_post_status"] != nil {
		t.Fatalf("%v", m)
	}

	// No temp files left behind.
	ents, _ := os.ReadDir(root)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

func TestStateFileDisabledSpoolAndNil(t *testing.T) {
	s := newStateFile("", "3.0.0", time.Now(), slog.Default())
	if s != nil {
		if s.doc.Spool.Supported {
			t.Fatal("no spool configured means supported=false")
		}
	}
	var nilState *stateFile
	nilState.Update(attempt{})
	nilState.Init(time.Second)
}
