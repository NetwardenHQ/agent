// Package registry holds the set of collectors and runs one collection cycle
// across all of them.
package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// collectorTimeout bounds a single collector's Collect call. A collector that
// ignores its context still cannot hold the cycle past this; its result is
// dropped and logged, and the others proceed. It is a variable so tests can
// shorten it.
var collectorTimeout = 10 * time.Second

// maxConcurrency caps how many collectors run at once. The collectors are
// I/O-bound (procfs, sockets, a few exec'd tools), so a small number keeps
// the agent's own CPU footprint flat on busy hosts while still overlapping
// the slow ones.
const maxConcurrency = 3

// Registry is the collector set. It is safe for concurrent use.
type Registry struct {
	mu         sync.RWMutex
	collectors []metrics.Collector
	logger     *slog.Logger

	// inFlight marks collectors whose Collect has not returned yet, possibly
	// from an earlier cycle that abandoned it. Such a collector is skipped
	// rather than started again: a collector that ignores its context would
	// otherwise gain one more stuck goroutine every cycle, and would run
	// concurrently with itself, which none of them is written to survive.
	flightMu sync.Mutex
	inFlight map[string]bool
	stuck    map[string]bool // skipped at least once since it last returned
}

// NewRegistry creates an empty registry.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{logger: logger, inFlight: map[string]bool{}}
}

// claim marks name in flight. It reports false when a previous call is still
// running.
func (r *Registry) claim(name string) bool {
	r.flightMu.Lock()
	defer r.flightMu.Unlock()
	if r.inFlight[name] {
		return false
	}
	r.inFlight[name] = true
	return true
}

func (r *Registry) release(name string) {
	r.flightMu.Lock()
	delete(r.inFlight, name)
	r.flightMu.Unlock()
}

// Register adds a collector. Names must be unique.
func (r *Registry) Register(collector metrics.Collector) error {
	if collector == nil {
		return fmt.Errorf("collector cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := collector.Name()
	for _, existing := range r.collectors {
		if existing.Name() == name {
			return fmt.Errorf("collector %s already registered", name)
		}
	}

	r.collectors = append(r.collectors, collector)
	r.logger.Info("registered collector", "name", name)
	return nil
}

// result is one collector's outcome for a cycle.
type result struct {
	name     string
	metrics  []metrics.Metric
	err      error
	duration time.Duration
}

// CollectAll runs every enabled collector for one cycle and returns the
// combined metrics. Collectors run concurrently, at most maxConcurrency at a
// time, each under collectorTimeout. A failing collector does not fail the
// cycle: its error is folded into the returned error and the metrics from the
// others are still returned, so the caller ships what it has.
//
// Each call is self-contained: goroutines, results and timeouts belong to
// this cycle only, so a collector that outlives the deadline cannot deliver
// its metrics into a later cycle.
//
// A collector still running from an earlier cycle is skipped and reported as
// a failure until it returns; see Registry.inFlight.
func (r *Registry) CollectAll(ctx context.Context) ([]metrics.Metric, error) {
	r.mu.RLock()
	enabled := make([]metrics.Collector, 0, len(r.collectors))
	for _, c := range r.collectors {
		if c.Enabled() {
			enabled = append(enabled, c)
		}
	}
	r.mu.RUnlock()

	if len(enabled) == 0 {
		return nil, nil
	}

	// Everything this cycle starts, including goroutines still queued for a
	// slot, ends with the cycle deadline as well as with the caller's ctx.
	cycleCtx, cancelCycle := context.WithTimeout(ctx, cycleDeadline())
	defer cancelCycle()

	// results is written by the collector goroutines and read once the cycle
	// is over. The mutex matters for the cycle that times out: an abandoned
	// goroutine may still be finishing while this call reads.
	var (
		resultsMu sync.Mutex
		results   = make([]result, len(enabled))
		sem       = make(chan struct{}, maxConcurrency)
		wg        sync.WaitGroup
	)
	store := func(i int, res result) {
		resultsMu.Lock()
		results[i] = res
		resultsMu.Unlock()
	}

	for i, c := range enabled {
		name := c.Name()
		if !r.claim(name) {
			store(i, result{name: name, err: errStillRunning})
			continue
		}
		wg.Add(1)
		go func(i int, c metrics.Collector) {
			defer wg.Done()
			defer r.release(name)

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-cycleCtx.Done():
				store(i, result{name: name, err: cycleCtx.Err()})
				return
			}

			cctx, cancel := context.WithTimeout(cycleCtx, collectorTimeout)
			defer cancel()

			start := time.Now()
			m, err := c.Collect(cctx)
			store(i, result{name: name, metrics: m, err: err, duration: time.Since(start)})
		}(i, c)
	}

	// Wait under the cycle deadline so one collector that ignores its
	// context cannot stall the cycle; its slot in results stays empty and
	// the goroutine is abandoned to finish (or not) on its own.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-cycleCtx.Done():
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.logger.Error("collection cycle timed out; shipping partial results",
			"timeout", cycleDeadline().String())
	}

	resultsMu.Lock()
	finished := make([]result, len(results))
	copy(finished, results)
	resultsMu.Unlock()

	var all []metrics.Metric
	var failures []string
	for _, res := range finished {
		if res.name == "" {
			continue // did not finish before the deadline
		}
		if res.err == errStillRunning {
			// Logged once per stuck run, not once per cycle.
			if r.noteStuck(res.name) {
				r.logger.Warn("collector still running from an earlier cycle; skipping it until it returns",
					"collector", res.name)
			}
			failures = append(failures, fmt.Sprintf("%s: %v", res.name, res.err))
			continue
		}
		r.clearStuck(res.name)
		if res.err != nil {
			r.logger.Warn("collector failed",
				"collector", res.name,
				"error", res.err,
				"duration", res.duration)
			failures = append(failures, fmt.Sprintf("%s: %v", res.name, res.err))
			continue
		}
		all = append(all, res.metrics...)
	}

	if len(failures) > 0 {
		return all, fmt.Errorf("partial collection failure (%d collectors failed): %v",
			len(failures), failures)
	}
	return all, nil
}

// errStillRunning marks a collector skipped because its previous Collect has
// not returned.
var errStillRunning = errors.New("still running from an earlier cycle; skipped")

// noteStuck records that name was skipped and reports whether this is the
// first skip of the current stuck run.
func (r *Registry) noteStuck(name string) bool {
	r.flightMu.Lock()
	defer r.flightMu.Unlock()
	if r.stuck == nil {
		r.stuck = map[string]bool{}
	}
	if r.stuck[name] {
		return false
	}
	r.stuck[name] = true
	return true
}

func (r *Registry) clearStuck(name string) {
	r.flightMu.Lock()
	defer r.flightMu.Unlock()
	if r.stuck[name] {
		delete(r.stuck, name)
		r.logger.Info("collector returned and is collecting again", "collector", name)
	}
}

// cycleDeadline is the most a whole cycle may take. Windows gets longer: its
// collectors go through WMI/COM, which is markedly slower than procfs. It is
// a variable so tests can shorten it.
var cycleDeadline = func() time.Duration {
	if runtime.GOOS == "windows" {
		return 40 * time.Second
	}
	return 30 * time.Second
}

// Snapshots gathers structured snapshots from every enabled collector that
// implements metrics.SnapshotProvider. Call it after CollectAll: it returns
// what that cycle staged and does not collect anything itself.
func (r *Registry) Snapshots() []metrics.Snapshot {
	r.mu.RLock()
	collectors := make([]metrics.Collector, len(r.collectors))
	copy(collectors, r.collectors)
	r.mu.RUnlock()

	var out []metrics.Snapshot
	for _, c := range collectors {
		provider, ok := c.(metrics.SnapshotProvider)
		if !ok || !c.Enabled() {
			continue
		}
		for _, snap := range provider.Snapshots() {
			if snap.Type == "" || snap.Payload == nil {
				r.logger.Warn("collector returned malformed snapshot, dropping",
					"collector", c.Name(), "type", snap.Type)
				continue
			}
			out = append(out, snap)
		}
	}
	return out
}

// ListCollectors returns the registered collector names in registration order.
func (r *Registry) ListCollectors() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.collectors))
	for i, c := range r.collectors {
		names[i] = c.Name()
	}
	return names
}

// GetCollector returns the collector with the given name, or nil.
func (r *Registry) GetCollector(name string) metrics.Collector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, c := range r.collectors {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// HealthCheck runs HealthCheck on every collector that implements it.
func (r *Registry) HealthCheck(ctx context.Context) map[string]error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]error)
	for _, c := range r.collectors {
		if hc, ok := c.(metrics.HealthChecker); ok {
			out[c.Name()] = hc.HealthCheck(ctx)
		}
	}
	return out
}

// Close closes every collector. It returns the last error seen; every
// collector is closed regardless.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error
	for _, c := range r.collectors {
		if err := c.Close(); err != nil {
			r.logger.Error("error closing collector", "name", c.Name(), "error", err)
			lastErr = err
		}
	}
	r.collectors = nil
	return lastErr
}
