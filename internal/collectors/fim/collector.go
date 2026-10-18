package fim

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// DefaultInterval is the walk cadence. Hourly: it bounds an attacker's
// undetected window to roughly the interval while keeping the steady-state
// cost near zero. The registry drives every collector on the global reporting
// interval (default 60s), so the collector throttles its own heavy work down
// to this.
const DefaultInterval = 1 * time.Hour

// defaultWalkTimeout is the budget for one full walk. Walks run in the
// background, outside the registry's per-collector timeout, because hashing a
// large ruleset can take far longer than one collection cycle. A walk that
// exceeds this is discarded, never reported as if complete.
const defaultWalkTimeout = 15 * time.Minute

// maxPendingChanges caps the unacknowledged changes kept and reported. Past
// it, further changes are still absorbed into the baseline but reported only
// as a count (changes_dropped), keeping both the post and the manifest
// bounded when something rewrites a whole tree.
const maxPendingChanges = 1000

// Rebuild reasons the agent can state. A rebuild without a reason means the
// manifest was absent: a first run, or a baseline that was deleted.
const (
	reasonRulesetChanged = "ruleset_changed"
	reasonRootsChanged   = "roots_changed"
	reasonUnreadable     = "manifest_unreadable"
	reasonUntrusted      = "manifest_untrusted"
)

// defaultManifestPath (per-platform, see statepath_*.go) is where the baseline
// lives: a dedicated state dir, not beside the config, owner-only.

// Collector performs periodic file integrity monitoring. It implements
// metrics.Collector (summary gauges) and metrics.SnapshotProvider (the
// file_integrity snapshot), and AckSnapshots, which the agent calls once a
// post carrying that snapshot has been accepted.
type Collector struct {
	hostname     string
	logger       *slog.Logger
	builder      metrics.MetricBuilder
	interval     time.Duration
	walkTimeout  time.Duration
	manifestPath string
	roots        []string
	realtime     bool

	// ctx bounds background walks; Close cancels it.
	ctx    context.Context
	cancel context.CancelFunc
	walks  sync.WaitGroup

	// work serializes the two paths that rewrite the baseline: the
	// background walk and the real-time re-check.
	work sync.Mutex
	// save serializes manifest writes, so an older state can never land on
	// disk after a newer one.
	save sync.Mutex

	permWarnOnce sync.Once
	watchOnce    sync.Once

	mu          sync.Mutex
	watcher     *watcher
	walking     bool
	walkStarted time.Time
	lastMetrics []metrics.Metric

	// The baseline. entries is replaced, never mutated in place, so a
	// reference taken under mu stays valid without it.
	loaded     bool
	manifestID string
	entries    map[string]Entry
	rootDev    map[string]uint64

	// What the platform should hear. report is the latest state; gen counts
	// its updates. unacked holds the changes and any rebuild not yet
	// acknowledged; inflight is what the last Snapshots call handed out.
	report      *reportState
	gen         uint64
	reportAcked bool
	unacked     Unacked
	inflight    *inflight
}

// reportState is the latest baseline summary for the file_integrity snapshot.
type reportState struct {
	entryCount  int
	digest      string
	truncated   bool
	unreadable  int
	evaluatedAt time.Time
}

// inflight records what one Snapshots call handed out, so AckSnapshots
// removes exactly that and nothing detected since.
type inflight struct {
	gen        uint64
	changes    int
	dropped    int
	rebuilt    bool
	manifestID string
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

// WithInterval overrides the walk cadence.
func WithInterval(d time.Duration) Option {
	return func(c *Collector) {
		if d > 0 {
			c.interval = d
		}
	}
}

// WithManifestPath overrides where the baseline is stored.
func WithManifestPath(p string) Option {
	return func(c *Collector) {
		if p != "" {
			c.manifestPath = p
		}
	}
}

// WithRealtime enables the fsnotify real-time layer. When off, FIM is
// periodic-walk only.
func WithRealtime(enabled bool) Option {
	return func(c *Collector) { c.realtime = enabled }
}

// WithRoots sets extra watched roots, appended to the compiled default ruleset.
func WithRoots(roots []string) Option {
	return func(c *Collector) {
		c.roots = append(c.roots, roots...)
	}
}

// NewCollector creates the FIM collector. The default ruleset for the host's
// platform is always included; WithRoots adds to it.
func NewCollector(hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname:     hostname,
		logger:       slog.Default(),
		builder:      metrics.NewBuilder().WithHostname(hostname),
		interval:     DefaultInterval,
		walkTimeout:  defaultWalkTimeout,
		manifestPath: defaultManifestPath(),
		roots:        defaultRoots(),
		reportAcked:  true,
	}
	for _, o := range opts {
		o(c)
	}
	c.roots = normalizeRoots(c.roots)
	c.ctx, c.cancel = context.WithCancel(context.Background())
	return c
}

// Name returns the collector name.
func (c *Collector) Name() string { return "fim" }

// Close stops any running walk and the real-time watcher.
func (c *Collector) Close() error {
	c.mu.Lock()
	c.cancel()
	w := c.watcher
	c.mu.Unlock()
	c.walks.Wait()
	if w != nil {
		w.close()
	}
	return nil
}

// Enabled reports whether FIM has anything to do. It is false when no roots
// resolve (a platform without a default ruleset and no operator-configured
// roots), so the collector stays inert rather than walking nothing every cycle.
func (c *Collector) Enabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.roots) > 0
}

// Collect starts a background walk when one is due and gives it until ctx
// expires to finish, so a small ruleset reports in the same cycle. A walk
// still running then carries on under its own budget and reports on a later
// cycle. Between walks, Collect re-checks paths nominated by the real-time
// watcher. The returned metrics describe the last finished walk or delta;
// before the first walk finishes there are none.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if len(c.roots) == 0 {
		return nil, nil
	}
	c.ensureWatcher()

	now := time.Now()
	var done chan struct{}
	c.mu.Lock()
	if !c.walking && c.ctx.Err() == nil &&
		(c.walkStarted.IsZero() || now.Sub(c.walkStarted) >= c.interval) {
		c.walking = true
		c.walkStarted = now
		done = make(chan struct{})
		c.walks.Add(1)
		go c.runWalk(done)
	}
	c.mu.Unlock()

	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
		}
	} else {
		c.realtimeDelta(ctx)
	}
	return c.currentMetrics(time.Now()), nil
}

// Snapshots returns the file_integrity snapshot while there is anything the
// platform has not acknowledged: a new walk or delta, queued changes, or a
// rebuild. It clears nothing; AckSnapshots does that after a successful post,
// so a failed send is offered again next cycle.
//
// A rebuild is reported on its own, with no changes, because the platform
// derives nothing from the changes of a rebuilt snapshot; changes queued
// alongside it follow once the rebuild is acknowledged.
func (c *Collector) Snapshots() []metrics.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	u := &c.unacked
	if c.report == nil ||
		(c.reportAcked && len(u.Changes) == 0 && u.Dropped == 0 && !u.Rebuilt) {
		return nil
	}

	fl := &inflight{gen: c.gen, manifestID: c.manifestID}
	changes := []Change{} // never nil: the platform expects a JSON array
	if u.Rebuilt {
		fl.rebuilt = true
	} else {
		changes = slices.Clone(u.Changes)
		if changes == nil {
			changes = []Change{}
		}
		fl.changes, fl.dropped = len(u.Changes), u.Dropped
	}
	c.inflight = fl

	r := c.report
	payload := map[string]any{
		"manifest_id":      c.manifestID,
		"ruleset_rev":      rulesetRevision,
		"entry_count":      r.entryCount,
		"digest":           r.digest,
		"roots":            c.roots,
		"changes":          changes,
		"baseline_rebuilt": fl.rebuilt,
		"walk_truncated":   r.truncated,
		"unreadable_files": r.unreadable,
		"evaluated_at":     r.evaluatedAt.UTC().Format(time.RFC3339),
	}
	if fl.rebuilt && u.RebuildReason != "" {
		payload["rebuild_reason"] = u.RebuildReason
	}
	if fl.dropped > 0 {
		payload["changes_dropped"] = fl.dropped
	}
	return []metrics.Snapshot{{Type: metrics.SnapshotFileIntegrity, Payload: payload}}
}

// AckSnapshots records that the snapshot from the last Snapshots call reached
// the platform: the changes and rebuild it carried are cleared, in memory and
// in the manifest. Anything detected after that call stays queued.
func (c *Collector) AckSnapshots() {
	c.mu.Lock()
	fl := c.inflight
	c.inflight = nil
	if fl == nil {
		c.mu.Unlock()
		return
	}
	persist := false
	if fl.rebuilt && c.unacked.Rebuilt && fl.manifestID == c.manifestID {
		c.unacked.Rebuilt, c.unacked.RebuildReason = false, ""
		persist = true
	}
	if fl.changes > 0 || fl.dropped > 0 {
		c.unacked.Changes = slices.Clone(c.unacked.Changes[fl.changes:])
		c.unacked.Dropped -= fl.dropped
		persist = true
	}
	if fl.gen == c.gen {
		c.reportAcked = true
	}
	c.mu.Unlock()

	if persist {
		c.persist()
	}
}

// ensureWatcher starts the fsnotify watcher once, if real-time is enabled.
func (c *Collector) ensureWatcher() {
	if !c.realtime {
		return
	}
	c.watchOnce.Do(func() {
		w := newWatcher(c.roots, c.logger)
		c.mu.Lock()
		c.watcher = w
		c.mu.Unlock()
	})
}

// runWalk is one background walk: load the stored baseline, walk the roots
// under the walk budget, diff, and stage the result. Holds c.work throughout,
// so real-time re-checks wait (their events stay queued) until it is done.
func (c *Collector) runWalk(done chan struct{}) {
	defer c.walks.Done()
	defer close(done)
	defer func() {
		c.mu.Lock()
		c.walking = false
		c.mu.Unlock()
	}()
	c.work.Lock()
	defer c.work.Unlock()

	ctx, cancel := context.WithTimeout(c.ctx, c.walkTimeout)
	defer cancel()

	start := time.Now()
	baseline, manifestID, rebuilt, reason := c.loadBaseline()
	res := buildEntries(ctx, c.roots)
	if ctx.Err() != nil {
		// Files the walk never reached would read as deleted. Keep the old
		// baseline and try again at the next interval.
		c.logger.Warn("FIM walk did not finish; result discarded",
			"budget", c.walkTimeout.String(), "files_seen", len(res.entries), "error", ctx.Err())
		return
	}

	current := res.entries
	changes := []Change{}
	if !rebuilt {
		changes = diff(baseline, current, res.covers)
	}
	if res.truncated {
		c.logger.Warn("FIM walk hit its size cap; unreached files are carried over unverified",
			"max_files", maxEntries, "max_dir_entries", maxDirEntries,
			"hint", "narrow fim_roots")
	}

	c.mu.Lock()
	c.loaded = true
	c.manifestID = manifestID
	c.entries = current
	c.rootDev = res.rootDev
	if rebuilt {
		c.unacked.Rebuilt, c.unacked.RebuildReason = true, reason
	}
	c.enqueue(changes)
	c.stageReport(current, res.truncated, len(changes), rebuilt, time.Now())
	c.mu.Unlock()

	c.persist()

	c.logger.Info("FIM walk complete",
		"files", len(current),
		"changes", len(changes),
		"baseline_rebuilt", rebuilt,
		"rebuild_reason", reason,
		"truncated", res.truncated,
		"roots", len(c.roots),
		"duration_ms", time.Since(start).Milliseconds())
}

// loadBaseline reads the stored manifest for a walk to diff against. A
// manifest that is missing, unreadable, untrusted, or built from a different
// ruleset or root set is not diffed against: a fresh baseline is built with a
// new id. Changes still queued from before are kept, since they were real;
// on the first load they are adopted from the manifest.
func (c *Collector) loadBaseline() (entries map[string]Entry, id string, rebuilt bool, reason string) {
	prior, insecure, err := loadManifest(c.manifestPath)
	if insecure {
		c.permWarnOnce.Do(func() {
			c.logger.Warn("FIM manifest is readable by other accounts",
				"path", c.manifestPath,
				"fix", "chmod 600 "+c.manifestPath)
		})
	}

	switch {
	case errors.Is(err, errManifestUntrusted):
		reason = reasonUntrusted
	case err != nil:
		reason = reasonUnreadable
	case prior == nil:
		// No stated reason: first run, or the baseline was deleted.
	case prior.RulesetRev != rulesetRevision:
		reason = reasonRulesetChanged
	case !slices.Equal(prior.Roots, c.roots):
		reason = reasonRootsChanged
	}
	if err != nil {
		c.logger.Warn("FIM manifest not used; rebuilding baseline", "reason", reason, "error", err)
	}

	c.mu.Lock()
	if !c.loaded && err == nil && prior != nil {
		c.unacked = prior.Unacked
	}
	c.mu.Unlock()

	if err != nil || prior == nil || reason != "" {
		return nil, newManifestID(), true, reason
	}
	return prior.Entries, prior.ID, false, ""
}

// realtimeDelta re-checks the paths the watcher nominated against the
// in-memory baseline and stages any changes. It skips the cycle when a walk
// holds c.work (the events stay queued and are re-checked against the walk's
// new baseline), and hands back unprocessed paths if ctx expires.
func (c *Collector) realtimeDelta(ctx context.Context) {
	if !c.work.TryLock() {
		return
	}
	defer c.work.Unlock()

	c.mu.Lock()
	w, loaded, baseline, rootDev := c.watcher, c.loaded, c.entries, c.rootDev
	c.mu.Unlock()
	if w == nil || !loaded {
		return
	}
	if w.takeOverflow() {
		c.mu.Lock()
		c.walkStarted = time.Time{} // events were lost: walk on the next cycle
		c.mu.Unlock()
	}

	paths := w.drainDirty()
	if len(paths) == 0 {
		return
	}
	slices.Sort(paths)

	var changes []Change
	var updated map[string]Entry
	mutate := func() map[string]Entry {
		if updated == nil {
			updated = cloneEntries(baseline)
		}
		return updated
	}

	for i, path := range paths {
		if ctx.Err() != nil {
			w.requeue(paths[i:])
			break
		}
		// A baseline path is in scope by construction (the walk recorded
		// it), even if its directory has since been removed.
		old, existed := baseline[path]
		if !existed && !c.inScope(path, rootDev) {
			continue
		}

		info, err := os.Lstat(path)
		var cur Entry
		ok := false
		if err == nil && info.Mode().IsRegular() {
			cur, ok = recordFile(ctx, path, info)
			if ctx.Err() != nil {
				w.requeue(paths[i:])
				break
			}
		} else if err != nil && !os.IsNotExist(err) {
			continue // transient; the walk will settle it
		}

		if !ok {
			// Gone, or no longer a regular file: the walk would drop it.
			if existed {
				changes = append(changes, deletedChange(old, detectedRealtime))
				delete(mutate(), path)
			}
			continue
		}
		if ch, changed := compareEntry(old, existed, &cur, detectedRealtime); changed {
			changes = append(changes, ch)
			mutate()[path] = cur
		}
	}

	if len(changes) == 0 {
		return
	}
	sortChanges(changes)

	c.mu.Lock()
	c.entries = updated
	c.enqueue(changes)
	truncated := c.report != nil && c.report.truncated
	c.stageReport(updated, truncated, len(changes), false, time.Now())
	c.mu.Unlock()

	c.persist()

	c.logger.Info("FIM real-time changes", "changes", len(changes), "files", len(updated))
}

// inScope reports whether a path nominated by the watcher is one the walk
// would record: a file root itself, or a file under a directory root within
// the walk's depth limit, reached without crossing a symlink or a mount and
// outside the pseudo-filesystems. Watching a single-file root's parent
// directory makes the watcher nominate its siblings; this is what drops them.
func (c *Collector) inScope(path string, rootDev map[string]uint64) bool {
	if isPseudoFS(path) {
		return false
	}
	for _, root := range c.roots {
		if path == root {
			return true
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if strings.Count(rel, string(filepath.Separator)) > maxWalkDepth {
			continue
		}
		rootInfo, err := os.Lstat(root)
		if err != nil || !rootInfo.IsDir() {
			continue
		}
		if c.reachable(root, filepath.Dir(path), rootDev) {
			return true
		}
	}
	return false
}

// reachable reports whether dir is reached from root through real directories
// on root's device, as the walk would reach it.
func (c *Collector) reachable(root, dir string, rootDev map[string]uint64) bool {
	dev, hasDev := rootDev[root]
	for d := dir; d != root; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() {
			return false
		}
		if hasDev {
			if dd, ok := deviceOf(fi); ok && dd != dev {
				return false
			}
		}
		if filepath.Dir(d) == d {
			return false
		}
	}
	return true
}

// enqueue adds changes to the unacknowledged queue, skipping exact repeats: a
// crash after a walk was staged but before it was persisted makes the next
// walk detect the same change again. Past maxPendingChanges changes are
// counted, not kept. Callers hold c.mu.
func (c *Collector) enqueue(changes []Change) {
	if len(changes) == 0 {
		return
	}
	type key struct {
		path      string
		kind      ChangeKind
		hash, was string
		mode      string
	}
	seen := make(map[key]struct{}, len(c.unacked.Changes))
	for _, ch := range c.unacked.Changes {
		seen[key{ch.Path, ch.Change, ch.Hash, ch.WasHash, ch.Mode}] = struct{}{}
	}
	for _, ch := range changes {
		k := key{ch.Path, ch.Change, ch.Hash, ch.WasHash, ch.Mode}
		if _, dup := seen[k]; dup {
			continue
		}
		if len(c.unacked.Changes) >= maxPendingChanges {
			c.unacked.Dropped++
			continue
		}
		seen[k] = struct{}{}
		c.unacked.Changes = append(c.unacked.Changes, ch)
	}
}

// stageReport publishes a new baseline summary. Callers hold c.mu.
func (c *Collector) stageReport(entries map[string]Entry, truncated bool, changes int, rebuilt bool, at time.Time) {
	unreadable := 0
	for _, e := range entries {
		if e.Unreadable {
			unreadable++
		}
	}
	c.report = &reportState{
		entryCount:  len(entries),
		digest:      rollupDigest(entries),
		truncated:   truncated,
		unreadable:  unreadable,
		evaluatedAt: at,
	}
	c.gen++
	c.reportAcked = false
	c.lastMetrics = c.emitMetrics(len(entries), changes, rebuilt, truncated, at)
}

// persist writes the current baseline and unacknowledged queue. A failure is
// logged and otherwise tolerated: the in-memory state stays authoritative and
// the next walk or ack writes it again.
func (c *Collector) persist() {
	c.save.Lock()
	defer c.save.Unlock()

	c.mu.Lock()
	m := &Manifest{
		ID:         c.manifestID,
		RulesetRev: rulesetRevision,
		Roots:      c.roots,
		Entries:    c.entries,
		Unacked: Unacked{
			Changes:       slices.Clone(c.unacked.Changes),
			Dropped:       c.unacked.Dropped,
			Rebuilt:       c.unacked.Rebuilt,
			RebuildReason: c.unacked.RebuildReason,
		},
	}
	c.mu.Unlock()

	if err := saveManifest(c.manifestPath, m); err != nil {
		c.logger.Warn("failed to persist FIM manifest", "path", c.manifestPath, "error", err)
	}
}

// currentMetrics re-stamps the last staged metrics for this cycle.
func (c *Collector) currentMetrics(now time.Time) []metrics.Metric {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.lastMetrics) == 0 {
		return nil
	}
	out := make([]metrics.Metric, 0, len(c.lastMetrics))
	for _, m := range c.lastMetrics {
		m.Timestamp = now
		out = append(out, m)
	}
	return out
}

func (c *Collector) emitMetrics(files, changes int, rebuilt, truncated bool, ts time.Time) []metrics.Metric {
	out := make([]metrics.Metric, 0, 4)
	add := func(name string, v float64) {
		if m, err := c.builder.WithTimestamp(ts).Gauge(name, v); err == nil {
			out = append(out, m)
		}
	}
	flag := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	add("fim_watched_files", float64(files))
	add("fim_changes_detected", float64(changes))
	add("fim_baseline_rebuilt", flag(rebuilt))
	add("fim_walk_truncated", flag(truncated))
	return out
}

// Verify interface compliance.
var (
	_ metrics.Collector        = (*Collector)(nil)
	_ metrics.SnapshotProvider = (*Collector)(nil)
)
