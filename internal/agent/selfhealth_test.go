package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/registry"
)

type scriptedCollector struct {
	name string
	err  error
}

func (c *scriptedCollector) Name() string  { return c.name }
func (c *scriptedCollector) Enabled() bool { return true }
func (c *scriptedCollector) Close() error  { return nil }
func (c *scriptedCollector) Collect(context.Context) ([]metrics.Metric, error) {
	if c.err != nil {
		return nil, c.err
	}
	return []metrics.Metric{{Name: c.name + "_value", Value: 1, Type: metrics.MetricTypeGauge, Timestamp: time.Now()}}, nil
}

// capturingTransmitter keeps the metrics of every post.
type capturingTransmitter struct{ posts [][]metrics.Metric }

func (t *capturingTransmitter) Send(_ context.Context, ms []metrics.Metric, _ []metrics.Snapshot) error {
	t.posts = append(t.posts, append([]metrics.Metric(nil), ms...))
	return nil
}
func (t *capturingTransmitter) Close() error { return nil }

func collectorUp(ms []metrics.Metric) map[string]float64 {
	out := map[string]float64{}
	for _, m := range ms {
		if m.Name == "agent_collector_up" {
			out[m.Labels["collector"]] = m.Value
		}
	}
	return out
}

func TestAgentReportsWhichCollectorsWork(t *testing.T) {
	reg := registry.NewRegistry(testLogger())
	disk := &scriptedCollector{name: "disk", err: errors.New("no such device")}
	for _, c := range []metrics.Collector{&scriptedCollector{name: "cpu"}, disk} {
		if err := reg.Register(c); err != nil {
			t.Fatal(err)
		}
	}
	tr := &capturingTransmitter{}
	a := &Agent{
		logger: testLogger(), registry: reg, transmitter: tr, hostname: "web-1",
		deltaTracker: metrics.NewDeltaTracker(metrics.DeltaConfig{Threshold: 1, MaxAge: time.Hour, Logger: testLogger()}),
	}

	_ = a.collectAndTransmit(context.Background())
	if len(tr.posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(tr.posts))
	}
	up := collectorUp(tr.posts[0])
	if up["cpu"] != 1 || up["disk"] != 0 || len(up) != 2 {
		t.Fatalf("agent_collector_up = %v, want cpu 1 and disk 0", up)
	}
	var sawDuration bool
	failing := -1.0
	for _, m := range tr.posts[0] {
		switch m.Name {
		case "agent_collection_seconds":
			sawDuration = true
		case "agent_collectors_failing":
			failing = m.Value
		}
	}
	if !sawDuration {
		t.Fatal("the cycle's duration was not reported")
	}
	if failing != 1 {
		t.Fatalf("agent_collectors_failing = %v, want 1", failing)
	}

	// The collector recovers: only what changed is sent.
	disk.err = nil
	_ = a.collectAndTransmit(context.Background())
	up = collectorUp(tr.posts[len(tr.posts)-1])
	if up["disk"] != 1 {
		t.Fatalf("recovery not reported: %v", up)
	}
	if _, resent := up["cpu"]; resent {
		t.Fatalf("an unchanged status was sent again: %v", up)
	}
	for _, m := range tr.posts[len(tr.posts)-1] {
		if m.Name == "agent_collectors_failing" && m.Value != 0 {
			t.Fatalf("agent_collectors_failing = %v after recovery", m.Value)
		}
	}
}

// When every collector fails there is still something to say: which ones.
func TestAgentReportsWhenEveryCollectorFails(t *testing.T) {
	reg := registry.NewRegistry(testLogger())
	if err := reg.Register(&scriptedCollector{name: "cpu", err: errors.New("boom")}); err != nil {
		t.Fatal(err)
	}
	tr := &capturingTransmitter{}
	a := &Agent{
		logger: testLogger(), registry: reg, transmitter: tr, hostname: "web-1",
		deltaTracker: metrics.NewDeltaTracker(metrics.DeltaConfig{Threshold: 1, MaxAge: time.Hour, Logger: testLogger()}),
	}
	_ = a.collectAndTransmit(context.Background())
	if len(tr.posts) != 1 || collectorUp(tr.posts[0])["cpu"] != 0 {
		t.Fatalf("posts: %+v", tr.posts)
	}
	if _, ok := collectorUp(tr.posts[0])["cpu"]; !ok {
		t.Fatal("the failing collector was not named")
	}
}
