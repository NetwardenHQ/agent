package cis

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"netwarden/internal/metrics"
)

// DefaultInterval is how often CIS evaluation runs.
//
// A full Level 1+2 pass reads several hundred files and execs systemctl and
// rpm. That is far too heavy for the agent's 60-second reporting interval, and
// posture changes on the order of hours, not seconds. The collector re-emits
// cached gauges between runs so the compliance-score series stays continuous.
const DefaultInterval = 1 * time.Hour

// Collector evaluates the operator's CIS profile against the local host.
//
// It implements metrics.Collector (scalar gauges: score, pass/fail counts) and
// metrics.SnapshotProvider (the per-check detail the UI renders).
type Collector struct {
	hostname string
	logger   *slog.Logger
	builder  metrics.MetricBuilder
	interval time.Duration

	// newProber constructs a per-run host prober. Swapped in tests.
	newProber func() Evaluator

	mu            sync.Mutex
	profile       *Profile
	lastCollected time.Time
	lastMetrics   []metrics.Metric
	pending       *metrics.Snapshot

	// lastRevision tracks the profile revision last evaluated, so a profile
	// edit in the UI forces a fresh run instead of waiting out the interval.
	lastRevision int

	unsupportedOnce sync.Once
}

// Option configures the collector.
type Option func(*Collector)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *Collector) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithInterval overrides the evaluation cadence.
func WithInterval(d time.Duration) Option {
	return func(c *Collector) {
		if d > 0 {
			c.interval = d
		}
	}
}

// withProber injects a prober, for tests.
func withProber(f func() Evaluator) Option {
	return func(c *Collector) {
		if f != nil {
			c.newProber = f
		}
	}
}

// NewCollector creates the CIS collector.
func NewCollector(hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname:  hostname,
		logger:    slog.Default(),
		builder:   metrics.NewBuilder().WithHostname(hostname),
		interval:  DefaultInterval,
		newProber: newHostProber,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name returns the collector name.
func (c *Collector) Name() string { return "cis" }

// Close releases resources (none held).
func (c *Collector) Close() error { return nil }

// SetProfile installs the profile fetched from /agent/config.
//
// A profile whose revision differs from the one last evaluated clears the
// throttle, so a change made in the UI is reflected on the next collection
// cycle rather than up to an hour later. That responsiveness is the whole
// point of the operator being able to edit a profile.
func (c *Collector) SetProfile(p *Profile) {
	c.mu.Lock()
	defer c.mu.Unlock()

	previous := c.profile
	c.profile = p

	switch {
	case p == nil && previous != nil:
		c.logger.Info("CIS profile removed; evaluation disabled")
		c.lastMetrics = nil
		c.pending = nil
	case p != nil && (previous == nil || previous.Revision != p.Revision):
		c.logger.Info("CIS profile updated",
			"revision", p.Revision,
			"benchmark", p.Benchmark,
			"levels", p.Levels,
			"enabled_checks", len(p.EnabledChecks),
			"waivers", len(p.Waivers))
		// Force a re-run on the next cycle.
		c.lastCollected = time.Time{}
	}
}

// Profile returns the installed profile, or nil.
func (c *Collector) Profile() *Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.profile
}

// Snapshots returns the CIS results from the most recent evaluation, then
// clears them. Throttled cycles return nil rather than re-shipping an
// unchanged report.
func (c *Collector) Snapshots() []metrics.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pending == nil {
		return nil
	}
	snap := *c.pending
	c.pending = nil
	return []metrics.Snapshot{snap}
}

// Enabled reports whether CIS evaluation should run. False until the operator
// defines a profile in the UI: this collector reads a great deal of system
// state, and doing that unasked is not a sensible default.
func (c *Collector) Enabled() bool {
	if !supportedPlatform() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.profile != nil
}

// Collect evaluates the profile and returns summary gauges.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if !supportedPlatform() {
		c.unsupportedOnce.Do(func() {
			c.logger.Info("CIS evaluation is only supported on Linux hosts")
		})
		return nil, nil
	}

	now := time.Now()

	c.mu.Lock()
	profile := c.profile
	throttled := !c.lastCollected.IsZero() &&
		now.Sub(c.lastCollected) < c.interval &&
		len(c.lastMetrics) > 0
	cached := c.lastMetrics
	c.mu.Unlock()

	if profile == nil {
		return nil, nil
	}

	if throttled {
		refreshed := make([]metrics.Metric, 0, len(cached))
		for _, m := range cached {
			m.Timestamp = now
			refreshed = append(refreshed, m)
		}
		return refreshed, nil
	}

	plan := profile.Resolve()
	if len(plan.Items) == 0 {
		c.logger.Warn("CIS profile selected no checks",
			"revision", plan.Revision,
			"unknown_checks", len(plan.UnknownChecks))
		return nil, nil
	}

	start := time.Now()
	results := c.run(ctx, plan)
	summary := Summarize(results)

	c.logger.Info("CIS evaluation complete",
		"revision", plan.Revision,
		"checks", summary.Total,
		"pass", summary.Pass,
		"fail", summary.Fail,
		"error", summary.Error,
		"not_applicable", summary.NotApplicable,
		"waived", summary.Waived,
		"score", summary.Score(),
		"duration_ms", time.Since(start).Milliseconds())

	if len(plan.UnknownChecks) > 0 {
		// The profile references checks this build does not carry. Surfaced
		// loudly because the alternative is those checks silently never
		// appearing in results.
		c.logger.Warn("CIS profile references checks unknown to this agent build",
			"count", len(plan.UnknownChecks),
			"first", plan.UnknownChecks[0],
			"hint", "upgrade the agent or remove them from the profile")
	}

	collected := c.emitMetrics(summary, plan, now)

	snap := metrics.Snapshot{
		Type: metrics.SnapshotCISResults,
		Payload: map[string]any{
			"revision":       plan.Revision,
			"benchmark":      benchmarkOrDefault(plan.Benchmark),
			"results":        results,
			"catalog":        CatalogEntries(),
			"summary":        summary,
			"score":          summary.Score(),
			"unknown_checks": plan.UnknownChecks,
			"catalog_size":   CatalogSize(),
			"levels":         plan.Levels,
			"evaluated_at":   now.UTC().Format(time.RFC3339),
		},
	}

	c.mu.Lock()
	c.lastCollected = now
	c.lastMetrics = collected
	c.lastRevision = plan.Revision
	c.pending = &snap
	c.mu.Unlock()

	return collected, nil
}

// run evaluates every plan item against a single prober, so its per-run caches
// are shared across all checks.
func (c *Collector) run(ctx context.Context, plan Plan) []Result {
	prober := c.newProber()
	results := make([]Result, 0, len(plan.Items))

	for _, item := range plan.Items {
		if err := ctx.Err(); err != nil {
			c.logger.Warn("CIS evaluation cancelled", "completed", len(results), "total", len(plan.Items))
			break
		}

		res := Evaluate(ctx, prober, item.Check, item.Expected)

		// A waived check is still evaluated so the UI can show the real state,
		// but its status is replaced so it raises no finding. The underlying
		// verdict is preserved in Detail rather than discarded.
		if item.Waived {
			res.Detail = "waived by profile; underlying status was " + string(res.Status)
			res.Status = StatusWaived
		}

		results = append(results, res)
	}

	return results
}

// emitMetrics builds the scalar gauge family. The detailed per-check results
// travel in the snapshot; these are for dashboards and alerting.
func (c *Collector) emitMetrics(s Summary, plan Plan, ts time.Time) []metrics.Metric {
	out := make([]metrics.Metric, 0, 7)

	add := func(name string, value float64, labels map[string]string) {
		m, err := c.builder.WithTimestamp(ts).GaugeWithLabels(name, value, labels)
		if err != nil {
			c.logger.Warn("failed to build CIS metric", "name", name, "error", err)
			return
		}
		out = append(out, m)
	}

	base := func() map[string]string {
		return map[string]string{
			"benchmark": benchmarkOrDefault(plan.Benchmark),
			"revision":  itoa(plan.Revision),
		}
	}

	add("cis_score_percent", s.Score(), base())
	add("cis_checks_total", float64(s.Total), base())
	add("cis_checks_passed", float64(s.Pass), base())
	add("cis_checks_failed", float64(s.Fail), base())
	add("cis_checks_error", float64(s.Error), base())
	add("cis_checks_not_applicable", float64(s.NotApplicable), base())
	add("cis_checks_waived", float64(s.Waived), base())

	return out
}

func benchmarkOrDefault(b string) string {
	if b == "" {
		return Benchmark
	}
	return b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Verify interface compliance at compile time.
var (
	_ metrics.Collector        = (*Collector)(nil)
	_ metrics.SnapshotProvider = (*Collector)(nil)
)
