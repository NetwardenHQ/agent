package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

func reading(name string, value float64, at time.Time) metrics.Metric {
	return metrics.Metric{Name: name, Value: value, Type: metrics.MetricTypeGauge, Timestamp: at}
}

func values(ms []metrics.Metric) []float64 {
	out := make([]float64, len(ms))
	for i, m := range ms {
		out[i] = m.Value
	}
	return out
}

func TestBacklogHandsBackTheOldestFirst(t *testing.T) {
	now := time.Now()
	b := newBacklog()
	b.add([]metrics.Metric{reading("m", 1, now.Add(-3*time.Minute)), reading("m", 2, now.Add(-2*time.Minute))})
	b.add([]metrics.Metric{reading("m", 3, now.Add(-time.Minute))})

	got := b.take(2, now)
	if fmt.Sprint(values(got)) != "[1 2]" || b.len() != 1 {
		t.Fatalf("took %v, %d left", values(got), b.len())
	}
	// The post failed again: they go back where they were.
	b.restore(got)
	if all := b.take(10, now); fmt.Sprint(values(all)) != "[1 2 3]" {
		t.Fatalf("after restore: %v", values(all))
	}
	if b.take(10, now) != nil || b.len() != 0 {
		t.Fatal("an empty backlog handed something back")
	}
}

func TestBacklogIsBoundedAndKeepsTheNewest(t *testing.T) {
	now := time.Now()
	b := &backlog{max: 5, maxAge: time.Hour}
	for i := 1; i <= 8; i++ {
		b.add([]metrics.Metric{reading("m", float64(i), now)})
	}
	if got := b.take(10, now); fmt.Sprint(values(got)) != "[4 5 6 7 8]" {
		t.Fatalf("kept %v, want the newest five", values(got))
	}
}

func TestBacklogDropsReadingsTooOldToBeWorthSending(t *testing.T) {
	now := time.Now()
	b := &backlog{max: 100, maxAge: time.Hour}
	b.add([]metrics.Metric{reading("m", 1, now.Add(-3*time.Hour)), reading("m", 2, now.Add(-30*time.Minute))})
	if got := b.take(10, now); fmt.Sprint(values(got)) != "[2]" {
		t.Fatalf("took %v", values(got))
	}
}

// outageTransmitter records every delivered reading with its timestamp.
type outageTransmitter struct {
	down     bool
	rejected bool
	got      []metrics.Metric
	posts    int
}

func (t *outageTransmitter) Send(_ context.Context, ms []metrics.Metric, _ []metrics.Snapshot) error {
	switch {
	case t.rejected:
		return fmt.Errorf("server rejected payload: status 400: %w", errPayloadRejected)
	case t.down:
		return errors.New("server unavailable")
	}
	t.posts++
	t.got = append(t.got, ms...)
	return nil
}
func (t *outageTransmitter) Close() error { return nil }

// counterCollector reports a counter that grows every cycle, the kind of
// series where a missing sample is a visible hole.
type counterCollector struct{ n float64 }

func (c *counterCollector) Name() string  { return "counter" }
func (c *counterCollector) Enabled() bool { return true }
func (c *counterCollector) Close() error  { return nil }
func (c *counterCollector) Collect(context.Context) ([]metrics.Metric, error) {
	c.n++
	return []metrics.Metric{{Name: "requests_total", Value: c.n, Type: metrics.MetricTypeCounter, Timestamp: time.Now()}}, nil
}

func delivered(ms []metrics.Metric, name string) []float64 {
	var out []float64
	for _, m := range ms {
		if m.Name == name {
			out = append(out, m.Value)
		}
	}
	return out
}

func TestReadingsTakenDuringAnOutageAreDeliveredAfterIt(t *testing.T) {
	tr := &outageTransmitter{}
	a := newRedeliveryAgent(t, &counterCollector{}, tr)
	a.backlog = newBacklog()

	_ = a.collectAndTransmit(context.Background()) // 1 delivered
	tr.down = true
	for i := 0; i < 3; i++ { // 2, 3, 4 taken while the server is away
		if err := a.collectAndTransmit(context.Background()); err == nil {
			t.Fatal("expected the failed post to surface")
		}
	}
	tr.down = false
	_ = a.collectAndTransmit(context.Background()) // 5, with what was kept

	got := delivered(tr.got, "requests_total")
	want := map[float64]bool{1: true, 2: true, 3: true, 4: true, 5: true}
	if len(got) != len(want) {
		t.Fatalf("server has %v, want every reading from 1 to 5 exactly once", got)
	}
	for _, v := range got {
		if !want[v] {
			t.Fatalf("server has %v, want every reading from 1 to 5 exactly once", got)
		}
		delete(want, v)
	}
	if a.backlog.len() != 0 {
		t.Fatalf("%d readings still kept after delivery", a.backlog.len())
	}
	// The first post, the post that got through after the outage, and one
	// batch of kept readings behind it.
	if tr.posts != 3 {
		t.Fatalf("%d posts, want 3", tr.posts)
	}
}

// An outage is not probed with an ever larger body: while posts fail, each
// attempt carries that cycle's readings only.
func TestKeptReadingsAreNotAttachedWhilePostsFail(t *testing.T) {
	tr := &sizeTransmitter{down: true}
	a := newRedeliveryAgent(t, &counterCollector{}, tr)
	a.backlog = newBacklog()

	for i := 0; i < 6; i++ {
		_ = a.collectAndTransmit(context.Background())
	}
	first, last := tr.attempts[0], tr.attempts[len(tr.attempts)-1]
	if last > first {
		t.Fatalf("attempts grew during the outage: %v", tr.attempts)
	}
	if a.backlog.len() == 0 {
		t.Fatal("nothing was kept")
	}

	// Healthy again: kept readings ride with fresh ones until they are gone.
	tr.down = false
	for i := 0; i < 3 && a.backlog.len() > 0; i++ {
		_ = a.collectAndTransmit(context.Background())
	}
	if a.backlog.len() != 0 {
		t.Fatalf("%d readings still kept", a.backlog.len())
	}
}

// sizeTransmitter records how many metrics each attempt carried.
type sizeTransmitter struct {
	down     bool
	attempts []int
}

func (t *sizeTransmitter) Send(_ context.Context, ms []metrics.Metric, _ []metrics.Snapshot) error {
	t.attempts = append(t.attempts, len(ms))
	if t.down {
		return errors.New("server unavailable")
	}
	return nil
}
func (t *sizeTransmitter) Close() error { return nil }

func TestKeptReadingsKeepTheTimeTheyWereTaken(t *testing.T) {
	tr := &outageTransmitter{down: true}
	a := newRedeliveryAgent(t, &counterCollector{}, tr)
	a.backlog = newBacklog()

	before := time.Now()
	_ = a.collectAndTransmit(context.Background())
	time.Sleep(30 * time.Millisecond)
	tr.down = false
	_ = a.collectAndTransmit(context.Background())

	var first metrics.Metric
	for _, m := range tr.got {
		if m.Name == "requests_total" && m.Value == 1 {
			first = m
		}
	}
	if first.Timestamp.IsZero() || first.Timestamp.Sub(before) > 20*time.Millisecond {
		t.Fatalf("the kept reading was restamped: taken about %v, delivered as %v", before, first.Timestamp)
	}
}

// A payload the server refuses is not kept: sending it again cannot succeed,
// and it would ride along with, and sink, every later post.
func TestARejectedPayloadIsNotKept(t *testing.T) {
	tr := &outageTransmitter{rejected: true}
	a := newRedeliveryAgent(t, &counterCollector{}, tr)
	a.backlog = newBacklog()

	_ = a.collectAndTransmit(context.Background())
	if a.backlog.len() != 0 {
		t.Fatalf("a rejected payload was kept (%d readings)", a.backlog.len())
	}
}

func TestReplayRoomFillsTheLastBatch(t *testing.T) {
	for _, tc := range []struct{ fresh, want int }{{0, 500}, {40, 460}, {499, 1}, {500, 500}, {730, 270}} {
		if got := replayRoom(tc.fresh); got != tc.want {
			t.Errorf("replayRoom(%d) = %d, want %d", tc.fresh, got, tc.want)
		}
	}
}
