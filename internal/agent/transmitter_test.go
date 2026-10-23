package agent

import (
	"encoding/json"
	"testing"

	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

// serverSnapshotTypes mirrors the snapshot types the server accepts. The
// server rejects the entire request when an unknown type appears, so a drift
// here costs a whole cycle of metrics, not just the snapshot.
var serverSnapshotTypes = map[string]bool{
	"ssh_config":         true,
	"listening_ports":    true,
	"installed_packages": true,
}

func newTestTransmitter(t *testing.T) *HTTPTransmitter {
	t.Helper()
	tr := &HTTPTransmitter{
		config:   &config.Config{TenantID: "abcdefghij"},
		logger:   testLogger(),
		version:  "2.1.0",
		hostname: "test-host",
	}
	tr.lastLatencyMs.Store(-1)
	return tr
}

// wire marshals a payload and returns its top-level JSON keys, which is what
// the server actually sees.
func wire(t *testing.T, p payload) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("payload does not marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("payload does not round-trip: %v", err)
	}
	return m
}

func TestCreatePayload_OmitsSnapshotsWhenEmpty(t *testing.T) {
	tr := newTestTransmitter(t)
	m := wire(t, tr.createPayload([]metrics.Metric{{Name: "cpu_usage_percent", Value: 1}}, nil))

	if _, present := m["snapshots"]; present {
		t.Error("snapshots key must be omitted when there are none; the server " +
			"treats an empty array differently from an absent field")
	}
}

func TestCreatePayload_ReportsSelfUpdateState(t *testing.T) {
	tr := newTestTransmitter(t)
	m := wire(t, tr.createPayload([]metrics.Metric{{Name: "cpu_usage_percent", Value: 1}}, nil))
	if _, present := m["self_update"]; present {
		t.Error("self_update must be omitted when no updater is wired")
	}

	tr.SetSelfUpdateState(func() string { return "enabled" })
	m = wire(t, tr.createPayload([]metrics.Metric{{Name: "cpu_usage_percent", Value: 1}}, nil))
	if got := string(m["self_update"]); got != `"enabled"` {
		t.Fatalf("self_update = %s, want \"enabled\"", got)
	}
}

func TestCreatePayload_SnapshotsMatchServerContract(t *testing.T) {
	tr := newTestTransmitter(t)
	snaps := []metrics.Snapshot{
		{
			Type: metrics.SnapshotSSHConfig,
			Payload: map[string]any{
				"port":              22,
				"permit_root_login": true,
				"password_auth":     true,
				"protocol_v1":       false,
				"x11_forwarding":    false,
				"empty_passwords":   false,
				"ciphers":           []string{"aes256-gcm@openssh.com"},
			},
		},
		{
			Type: metrics.SnapshotListeningPorts,
			Payload: map[string]any{
				"ports": []map[string]any{
					{"proto": "tcp", "port": 22, "bind_addr": "0.0.0.0"},
				},
				"open_ports_count":        1,
				"public_bind_count":       1,
				"management_ports_public": 1,
			},
		},
	}

	payload := tr.createPayload([]metrics.Metric{{Name: "cpu_usage_percent", Value: 1}}, snaps)

	// Round-trip through JSON: that is what the server actually parses.
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("payload does not marshal: %v", err)
	}

	var decoded struct {
		Version   string `json:"version"`
		Hostname  string `json:"hostname"`
		TenantID  string `json:"tenant_id"`
		Snapshots []struct {
			Type    string         `json:"type"`
			Payload map[string]any `json:"payload"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("payload does not round-trip: %v", err)
	}

	if len(decoded.Snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(decoded.Snapshots))
	}
	for _, s := range decoded.Snapshots {
		if !serverSnapshotTypes[s.Type] {
			t.Errorf("snapshot type %q is not in the server's accepted enum", s.Type)
		}
		if len(s.Payload) == 0 {
			t.Errorf("snapshot %q has an empty payload; the server schema requires an object", s.Type)
		}
	}

	// The identity fields the server needs to resolve the host must survive.
	if decoded.Version == "" || decoded.Hostname == "" || decoded.TenantID == "" {
		t.Errorf("payload lost identity fields: %+v", decoded)
	}
}

func TestCreatePayload_TruncatesToServerLimit(t *testing.T) {
	tr := newTestTransmitter(t)

	snaps := make([]metrics.Snapshot, maxSnapshotsPerPayload+5)
	for i := range snaps {
		snaps[i] = metrics.Snapshot{
			Type:    metrics.SnapshotListeningPorts,
			Payload: map[string]any{"ports": []any{}},
		}
	}

	got := tr.createPayload(nil, snaps).Snapshots
	if len(got) != maxSnapshotsPerPayload {
		t.Errorf("expected truncation to %d, got %d; the server rejects the whole "+
			"request above its cap", maxSnapshotsPerPayload, len(got))
	}
}

func TestCreatePayload_SnapshotOnlyCycle(t *testing.T) {
	// A cycle where every metric was delta-filtered away must still deliver
	// the snapshot, otherwise a stable host never reports posture at all.
	tr := newTestTransmitter(t)
	payload := tr.createPayload(nil, []metrics.Snapshot{{
		Type:    metrics.SnapshotSSHConfig,
		Payload: map[string]any{"permit_root_login": false},
	}})

	if _, ok := wire(t, payload)["snapshots"]; !ok {
		t.Fatal("snapshot dropped on a metric-free cycle")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("empty payload")
	}
}

func TestCreatePayload_LatencySentinel(t *testing.T) {
	tr := newTestTransmitter(t)

	// -1 means "never measured" and must not be reported as a real 0ms.
	snap := []metrics.Snapshot{{Type: metrics.SnapshotSSHConfig, Payload: map[string]any{"a": 1}}}
	if _, present := wire(t, tr.createPayload(nil, snap))["agent_latency"]; present {
		t.Error("agent_latency must be omitted before the first measurement")
	}

	tr.lastLatencyMs.Store(0)
	if _, present := wire(t, tr.createPayload(nil, snap))["agent_latency"]; !present {
		t.Error("a genuine 0ms measurement must be reported")
	}
}

func TestSnapshotJSONFieldNames(t *testing.T) {
	// The server reads `type` and `payload`; Go field names would be wrong.
	raw, err := json.Marshal(metrics.Snapshot{
		Type:    metrics.SnapshotInstalledPackages,
		Payload: map[string]any{"packages": []any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"type", "payload"} {
		if _, ok := m[key]; !ok {
			t.Errorf("snapshot JSON missing %q key; got %s", key, raw)
		}
	}
}
