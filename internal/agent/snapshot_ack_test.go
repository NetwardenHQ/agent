package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/registry"
)

// ackingCollector stands in for FIM: its snapshot stays staged until acked.
type ackingCollector struct{ acks int }

func (c *ackingCollector) Name() string { return "acking" }
func (c *ackingCollector) Collect(context.Context) ([]metrics.Metric, error) {
	return nil, nil
}
func (c *ackingCollector) Enabled() bool { return true }
func (c *ackingCollector) Close() error  { return nil }
func (c *ackingCollector) Snapshots() []metrics.Snapshot {
	return []metrics.Snapshot{{Type: metrics.SnapshotFileIntegrity, Payload: map[string]any{"x": 1}}}
}
func (c *ackingCollector) AckSnapshots() { c.acks++ }

type flakyTransmitter struct{ fail bool }

func (t *flakyTransmitter) Send(context.Context, []metrics.Metric, []metrics.Snapshot) error {
	if t.fail {
		return errors.New("post failed")
	}
	return nil
}
func (t *flakyTransmitter) Close() error { return nil }

func TestSnapshotsAckedOnlyAfterSuccessfulPost(t *testing.T) {
	reg := registry.NewRegistry(slog.Default())
	col := &ackingCollector{}
	if err := reg.Register(col); err != nil {
		t.Fatal(err)
	}
	tr := &flakyTransmitter{fail: true}
	a := &Agent{
		logger:       slog.Default(),
		registry:     reg,
		transmitter:  tr,
		deltaTracker: metrics.NewDeltaTracker(metrics.DeltaConfig{Enabled: true}),
	}

	if err := a.collectAndTransmit(context.Background()); err == nil {
		t.Fatal("expected the failed post to surface")
	}
	if col.acks != 0 {
		t.Fatalf("snapshot acked after a failed post (%d acks)", col.acks)
	}

	tr.fail = false
	if err := a.collectAndTransmit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if col.acks != 1 {
		t.Fatalf("acks = %d after a successful post, want 1", col.acks)
	}
}
