package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/spool"
)

func trustedSpool(t *testing.T) (string, *spool.Reader) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	os.Mkdir(filepath.Join(dir, "events"), 0o700)
	return dir, spool.New(dir, spool.WithOwnerUID(os.Getuid()), spool.WithClock(time.Now))
}

func line(i int) string {
	return fmt.Sprintf(`{"v":1,"type":"ssh.login","severity":"info","title":"t","occurred_at":"2026-10-18T13:00:00Z","dedupe_key":"k%d"}`+"\n", i)
}

func TestWithExtrasAddsIdentityEverywhereAndAcksOnce(t *testing.T) {
	dir, sp := trustedSpool(t)
	p := filepath.Join(dir, "events", "a.jsonl")
	os.WriteFile(p, []byte(line(1)), 0o600)
	a := &Agent{logger: slog.Default(), identityEnabled: true, spool: sp}

	snaps, ack := a.withExtras([]metrics.Snapshot{{Type: "ssh_config", Payload: map[string]any{}}}, nil)
	if snaps[0].Type != metrics.SnapshotDeviceIdentity || snaps[0].Payload["role"] != "server" {
		t.Fatalf("identity first with server role: %+v", snaps[0])
	}
	if len(snaps) != 3 || snaps[2].Type != metrics.SnapshotEvents {
		t.Fatalf("%d snapshots", len(snaps))
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("not deleted before ack")
	}
	ack()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("deleted after ack")
	}
}

func TestWithExtrasRespectsSnapshotAndByteLimits(t *testing.T) {
	dir, sp := trustedSpool(t)
	os.WriteFile(filepath.Join(dir, "events", "a.jsonl"), []byte(line(1)), 0o600)
	a := &Agent{logger: slog.Default(), identityEnabled: true, spool: sp}

	// 15 registry snapshots + identity = 16: events must be deferred.
	base := make([]metrics.Snapshot, 15)
	for i := range base {
		base[i] = metrics.Snapshot{Type: "ssh_config", Payload: map[string]any{}}
	}
	snaps, ack := a.withExtras(base, nil)
	if len(snaps) != 16 || ack != nil {
		t.Fatalf("len=%d ack=%v", len(snaps), ack != nil)
	}

	// A near-1MB registry snapshot leaves no room for spool data.
	big := []metrics.Snapshot{{Type: "installed_packages", Payload: map[string]any{"x": strings.Repeat("a", maxPostBytes-postSlack-100)}}}
	snaps, ack = a.withExtras(big, nil)
	if len(snaps) != 2 || ack != nil {
		t.Fatalf("events must be deferred when the post is full, got %d", len(snaps))
	}
	if _, err := os.Stat(filepath.Join(dir, "events", "a.jsonl")); err != nil {
		t.Fatal("deferred events stay on disk")
	}
}

func TestWithExtrasDisabledWithoutSpool(t *testing.T) {
	a := &Agent{logger: slog.Default(), identityEnabled: true}
	snaps, ack := a.withExtras(nil, nil)
	if len(snaps) != 1 || snaps[0].Type != metrics.SnapshotDeviceIdentity {
		t.Fatal("identity still sent without a spool")
	}
	if ack != nil {
		ack()
	}
}

func TestWithExtrasBudgetMatchesTheWireSize(t *testing.T) {
	// The wire form carries host_id on every metric, so a long hostname and a
	// full batch must still fit the 1 MB budget.
	dir, sp := trustedSpool(t)
	detail := strings.Repeat("d", 1900)
	var b strings.Builder
	for i := range 500 {
		fmt.Fprintf(&b, `{"v":1,"type":"ssh.login","severity":"info","title":"t","detail":"%s","occurred_at":"2026-10-18T13:00:00Z","dedupe_key":"k%d"}`+"\n", detail, i)
	}
	os.WriteFile(filepath.Join(dir, "events", "a.jsonl"), []byte(b.String()), 0o600)

	host := strings.Repeat("h", 250)
	tr := newTestTransmitter(t)
	tr.hostname = host
	a := &Agent{logger: slog.Default(), identityEnabled: true, spool: sp, hostname: host, transmitter: tr}

	batch := make([]metrics.Metric, 1000)
	for i := range batch {
		batch[i] = metrics.Metric{Name: fmt.Sprintf("metric_%d", i), Value: 1, Timestamp: time.Now()}
	}
	snaps, _ := a.withExtras(nil, batch)
	raw, err := json.Marshal(tr.createPayload(batch, snaps))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxPostBytes {
		t.Fatalf("post is %d bytes, over the %d budget", len(raw), maxPostBytes)
	}
}
