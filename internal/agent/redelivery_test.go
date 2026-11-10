package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/registry"
)

// oneShotCollector reports steady gauges and stages each snapshot once, the
// way the inventory collectors do: a drained snapshot is gone until the next
// collection interval, hours later.
type oneShotCollector struct {
	staged []metrics.Snapshot
}

func (c *oneShotCollector) Name() string  { return "oneshot" }
func (c *oneShotCollector) Enabled() bool { return true }
func (c *oneShotCollector) Close() error  { return nil }
func (c *oneShotCollector) Collect(context.Context) ([]metrics.Metric, error) {
	return []metrics.Metric{
		{Name: "cpu_usage_percent", Value: 40, Type: metrics.MetricTypeGauge, Timestamp: time.Now()},
		{Name: "memory_usage_percent", Value: 60, Type: metrics.MetricTypeGauge, Timestamp: time.Now()},
	}, nil
}
func (c *oneShotCollector) Snapshots() []metrics.Snapshot {
	out := c.staged
	c.staged = nil
	return out
}

// recordingTransmitter fails while down and records what each post carried.
type recordingTransmitter struct {
	down  bool
	posts []post
}

type post struct {
	metrics   []string
	snapshots []string
}

func (t *recordingTransmitter) Send(_ context.Context, ms []metrics.Metric, snaps []metrics.Snapshot) error {
	if t.down {
		return errors.New("server unavailable")
	}
	var p post
	for _, m := range ms {
		p.metrics = append(p.metrics, m.Name)
	}
	for _, s := range snaps {
		p.snapshots = append(p.snapshots, s.Type)
	}
	t.posts = append(t.posts, p)
	return nil
}
func (t *recordingTransmitter) Close() error { return nil }

func newRedeliveryAgent(t *testing.T, col metrics.Collector, tr MetricTransmitter) *Agent {
	t.Helper()
	reg := registry.NewRegistry(testLogger())
	if err := reg.Register(col); err != nil {
		t.Fatal(err)
	}
	return &Agent{
		logger:       testLogger(),
		registry:     reg,
		transmitter:  tr,
		deltaTracker: metrics.NewDeltaTracker(metrics.DeltaConfig{Threshold: 1, MaxAge: time.Hour, Logger: testLogger()}),
	}
}

func TestMetricsFromAFailedPostAreSentAgain(t *testing.T) {
	col := &oneShotCollector{}
	tr := &recordingTransmitter{down: true}
	a := newRedeliveryAgent(t, col, tr)

	if err := a.collectAndTransmit(context.Background()); err == nil {
		t.Fatal("expected the failed post to surface")
	}
	tr.down = false
	if err := a.collectAndTransmit(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The values did not change between the two cycles. Only the failed post
	// makes them due again.
	if len(tr.posts) != 1 || !contains(tr.posts[0].metrics, "cpu_usage_percent") || !contains(tr.posts[0].metrics, "memory_usage_percent") {
		t.Fatalf("after recovery the server received %+v, want both gauges", tr.posts)
	}
	if err := a.collectAndTransmit(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range tr.posts[1:] {
		if contains(p.metrics, "cpu_usage_percent") || contains(p.metrics, "memory_usage_percent") {
			t.Fatalf("unchanged gauges sent again after delivery: %+v", p)
		}
	}
}

func TestSnapshotsFromAFailedPostAreSentAgain(t *testing.T) {
	col := &oneShotCollector{staged: []metrics.Snapshot{
		{Type: metrics.SnapshotInstalledPackages, Payload: map[string]any{"count": 1200}},
		{Type: metrics.SnapshotSSHConfig, Payload: map[string]any{"v": 1}},
	}}
	tr := &recordingTransmitter{down: true}
	a := newRedeliveryAgent(t, col, tr)

	_ = a.collectAndTransmit(context.Background())
	_ = a.collectAndTransmit(context.Background()) // still down; the collector has nothing new staged

	// A newer snapshot of a type replaces the one waiting; other types wait on.
	col.staged = []metrics.Snapshot{{Type: metrics.SnapshotSSHConfig, Payload: map[string]any{"v": 2}}}
	tr.down = false
	if err := a.collectAndTransmit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(tr.posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(tr.posts))
	}
	got := tr.posts[0].snapshots
	if len(got) != 2 || !contains(got, metrics.SnapshotInstalledPackages) || !contains(got, metrics.SnapshotSSHConfig) {
		t.Fatalf("snapshots delivered after recovery: %v", got)
	}

	// Delivered: nothing is offered a second time.
	if err := a.collectAndTransmit(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range tr.posts[1:] {
		if len(p.snapshots) != 0 {
			t.Fatalf("a delivered snapshot was sent again: %v", p.snapshots)
		}
	}
}

func TestWaitingSnapshotsKeepEveryDeltaAndTheNewestState(t *testing.T) {
	waiting := []metrics.Snapshot{
		{Type: metrics.SnapshotK8sHealthDelta, Payload: map[string]any{"n": 1}},
		{Type: metrics.SnapshotSSHConfig, Payload: map[string]any{"v": 1}},
	}
	fresh := []metrics.Snapshot{
		{Type: metrics.SnapshotK8sHealthDelta, Payload: map[string]any{"n": 2}},
		{Type: metrics.SnapshotSSHConfig, Payload: map[string]any{"v": 2}},
	}
	got := mergeSnapshots(waiting, fresh)
	if len(got) != 3 {
		t.Fatalf("merged %d snapshots, want both deltas and one ssh_config: %+v", len(got), got)
	}
	// Deltas are transitions: every one counts, oldest first.
	if got[0].Type != metrics.SnapshotK8sHealthDelta || got[0].Payload["n"] != 1 {
		t.Fatalf("oldest delta is not first: %+v", got)
	}
	for _, s := range got {
		if s.Type == metrics.SnapshotSSHConfig && s.Payload["v"] != 2 {
			t.Fatalf("a stale ssh_config survived: %+v", s)
		}
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
