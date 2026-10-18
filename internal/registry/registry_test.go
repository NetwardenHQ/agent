package registry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// fakeCollector is a collector whose behavior the test scripts.
type fakeCollector struct {
	name    string
	enabled bool
	collect func(ctx context.Context) ([]metrics.Metric, error)
	closed  atomic.Bool
}

func (f *fakeCollector) Name() string  { return f.name }
func (f *fakeCollector) Enabled() bool { return f.enabled }
func (f *fakeCollector) Close() error  { f.closed.Store(true); return nil }
func (f *fakeCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	return f.collect(ctx)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func one(name string) []metrics.Metric {
	return []metrics.Metric{{Name: name, Value: 1, Timestamp: time.Now()}}
}

func TestRegister_RejectsDuplicateNames(t *testing.T) {
	r := NewRegistry(quiet())
	c := &fakeCollector{name: "cpu", enabled: true}
	if err := r.Register(c); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(c); err == nil {
		t.Fatal("duplicate name must be rejected")
	}
	if err := r.Register(nil); err == nil {
		t.Fatal("nil collector must be rejected")
	}
}

func TestCollectAll_PartialFailureStillReturnsMetrics(t *testing.T) {
	r := NewRegistry(quiet())
	_ = r.Register(&fakeCollector{name: "ok", enabled: true, collect: func(context.Context) ([]metrics.Metric, error) {
		return one("ok_metric"), nil
	}})
	_ = r.Register(&fakeCollector{name: "broken", enabled: true, collect: func(context.Context) ([]metrics.Metric, error) {
		return nil, errors.New("boom")
	}})
	_ = r.Register(&fakeCollector{name: "off", enabled: false, collect: func(context.Context) ([]metrics.Metric, error) {
		t.Error("disabled collector must not run")
		return nil, nil
	}})

	got, err := r.CollectAll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "broken: boom") {
		t.Fatalf("expected the failure to be reported, got %v", err)
	}
	if len(got) != 1 || got[0].Name != "ok_metric" {
		t.Fatalf("metrics from the healthy collector must survive a sibling's failure, got %v", got)
	}
}

func TestCollectAll_SlowCollectorDoesNotLeakIntoNextCycle(t *testing.T) {
	old := collectorTimeout
	collectorTimeout = 200 * time.Millisecond
	t.Cleanup(func() { collectorTimeout = old })

	release := make(chan struct{})
	r := NewRegistry(quiet())
	_ = r.Register(&fakeCollector{name: "slow", enabled: true, collect: func(ctx context.Context) ([]metrics.Metric, error) {
		select {
		case <-release:
			return one("slow_metric"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	_ = r.Register(&fakeCollector{name: "fast", enabled: true, collect: func(context.Context) ([]metrics.Metric, error) {
		return one("fast_metric"), nil
	}})

	// Cycle 1: the slow collector times out (its context expires at
	// collectorTimeout); the fast one's metric must still come back.
	ctx, cancel := context.WithTimeout(context.Background(), 2*collectorTimeout)
	defer cancel()
	got, err := r.CollectAll(ctx)
	if err == nil {
		t.Fatal("expected the timed-out collector to be reported")
	}
	if len(got) != 1 || got[0].Name != "fast_metric" {
		t.Fatalf("cycle 1 should carry exactly the fast metric, got %v", got)
	}

	// Cycle 2: nothing from cycle 1 may appear, and each collector's result
	// belongs to this call.
	close(release)
	got, err = r.CollectAll(context.Background())
	if err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("cycle 2 should carry exactly two metrics, got %v", got)
	}
}

func TestCollectAll_RunsConcurrentlyWithBoundedParallelism(t *testing.T) {
	r := NewRegistry(quiet())
	var running, peak atomic.Int32
	for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
		_ = r.Register(&fakeCollector{name: name, enabled: true, collect: func(context.Context) ([]metrics.Metric, error) {
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			running.Add(-1)
			return one("m"), nil
		}})
	}

	start := time.Now()
	got, err := r.CollectAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("expected 6 metrics, got %d", len(got))
	}
	if p := peak.Load(); p < 2 || p > maxConcurrency {
		t.Fatalf("peak parallelism %d, want between 2 and %d", p, maxConcurrency)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("six 20ms collectors took %v; they are not running concurrently", elapsed)
	}
}

func TestClose_ClosesEveryCollector(t *testing.T) {
	r := NewRegistry(quiet())
	a := &fakeCollector{name: "a"}
	b := &fakeCollector{name: "b"}
	_ = r.Register(a)
	_ = r.Register(b)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !a.closed.Load() || !b.closed.Load() {
		t.Fatal("Close must close every collector")
	}
	if names := r.ListCollectors(); len(names) != 0 {
		t.Fatalf("registry still lists %v after Close", names)
	}
}

// shortCycle shrinks the cycle deadline for one test.
func shortCycle(t *testing.T, d time.Duration) {
	t.Helper()
	old := cycleDeadline
	cycleDeadline = func() time.Duration { return d }
	t.Cleanup(func() { cycleDeadline = old })
}

func TestCollectAll_StuckCollectorIsNotStartedAgain(t *testing.T) {
	shortCycle(t, 100*time.Millisecond)
	release := make(chan struct{})
	var calls atomic.Int32
	r := NewRegistry(quiet())
	_ = r.Register(&fakeCollector{name: "stuck", enabled: true, collect: func(context.Context) ([]metrics.Metric, error) {
		calls.Add(1)
		<-release // ignores ctx on purpose
		return one("late"), nil
	}})
	_ = r.Register(&fakeCollector{name: "fast", enabled: true, collect: func(context.Context) ([]metrics.Metric, error) {
		return one("fast_metric"), nil
	}})

	if got, _ := r.CollectAll(context.Background()); len(got) != 1 || got[0].Name != "fast_metric" {
		t.Fatalf("cycle 1 should ship the fast metric only, got %v", got)
	}
	got, err := r.CollectAll(context.Background())
	if calls.Load() != 1 {
		t.Fatalf("a collector still running was started again (%d calls)", calls.Load())
	}
	if err == nil || !strings.Contains(err.Error(), "stuck: still running") {
		t.Fatalf("the skip must be reported, got %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the healthy collector must still ship, got %v", got)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got, err := r.CollectAll(context.Background()); err == nil && len(got) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the collector never resumed after it returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected exactly one more call after it returned, got %d", calls.Load())
	}
}

func TestCollectAll_QueuedCollectorGivesUpAtTheCycleDeadline(t *testing.T) {
	shortCycle(t, 100*time.Millisecond)
	release := make(chan struct{})
	defer close(release)

	// Which goroutine wins a slot is up to the scheduler; retry until the
	// stuck collectors took every slot in cycle 1.
	for attempt := 0; attempt < 50; attempt++ {
		r := NewRegistry(quiet())
		for _, name := range []string{"s1", "s2", "s3"} {
			_ = r.Register(&fakeCollector{name: name, enabled: true, collect: func(context.Context) ([]metrics.Metric, error) {
				<-release
				return nil, nil
			}})
		}
		var ran atomic.Int32
		_ = r.Register(&fakeCollector{name: "queued", enabled: true, collect: func(context.Context) ([]metrics.Metric, error) {
			ran.Add(1)
			return one("queued_metric"), nil
		}})

		_, _ = r.CollectAll(context.Background())
		if ran.Load() != 0 {
			continue // it got a slot; nothing was queued
		}
		time.Sleep(20 * time.Millisecond)

		// Cycle 2: "queued" must have given up and released its in-flight
		// mark, so it runs now.
		got, _ := r.CollectAll(context.Background())
		if len(got) != 1 || got[0].Name != "queued_metric" {
			t.Fatalf("a collector queued past the cycle deadline never gave up: %v", got)
		}
		return
	}
	t.Skip("scheduler never queued the fourth collector")
}
