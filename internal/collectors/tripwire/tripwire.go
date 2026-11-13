// Package tripwire watches for ransomware: decoy "canary" files nobody should
// ever touch, bursts of file changes in protected folders, changed files
// that look encrypted, and, on a Synology NAS, the canaries' copies in the
// newest share snapshot.
//
// A canary is checked every collection (about a minute). Any change,
// deletion or rename of one, or a canary that has become unreadable, is
// reported at once; the platform alerts on it as critical. Folder walks run
// in the background on their own interval, because a large share takes tens
// of seconds to walk.
package tripwire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/sharesnap"
)

const (
	// maxCanaryBytes bounds the hashing of one canary.
	maxCanaryBytes = 64 << 20
	// maxReported caps the per-item series in one collection.
	maxReported = 20
)

// Canary states.
const (
	stateIntact     = "intact"
	stateModified   = "modified"
	stateMissing    = "missing"
	stateUnreadable = "unreadable"
)

type canarySpec struct {
	path   string
	pinned string // sha256 the canary must have, from the config; "" when learned
}

var pinRe = regexp.MustCompile(`^(.*)@sha256:([0-9a-fA-F]{64})$`)

// parseCanary reads one config entry: a path, optionally "@sha256:<hex>".
func parseCanary(entry string) canarySpec {
	entry = strings.TrimSpace(entry)
	if m := pinRe.FindStringSubmatch(entry); m != nil {
		return canarySpec{path: filepath.Clean(m[1]), pinned: strings.ToLower(m[2])}
	}
	return canarySpec{path: filepath.Clean(entry)}
}

// Collector is the ransomware tripwire.
type Collector struct {
	hostname     string
	logger       *slog.Logger
	builder      metrics.MetricBuilder
	canaries     []canarySpec
	folders      []string
	statePath    string
	volumes      string
	walkEvery    time.Duration
	walkDeadline time.Duration
	now          func() time.Time
	syncWalks    bool
	saveWarned   string
	onWalk       func() // tests: called at the start of each folder walk

	mu      sync.Mutex
	st      *state
	walking bool
	results map[string]walkResult
	// attempted is when each folder's last walk started, whatever its
	// outcome: walks are paced by it, so a folder that fails or times out
	// waits for the interval like any other.
	attempted map[string]time.Time
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

// WithCanaries sets the canary files ("path" or "path@sha256:<hex>").
func WithCanaries(entries []string) Option {
	return func(c *Collector) {
		for _, e := range entries {
			if strings.TrimSpace(e) != "" {
				c.canaries = append(c.canaries, parseCanary(e))
			}
		}
	}
}

// WithFolders sets the folders whose changes are watched.
func WithFolders(dirs []string) Option {
	return func(c *Collector) {
		for _, d := range dirs {
			if d = strings.TrimSpace(d); d != "" {
				c.folders = append(c.folders, filepath.Clean(d))
			}
		}
	}
}

// WithStatePath sets where baselines are kept.
func WithStatePath(p string) Option {
	return func(c *Collector) {
		if p != "" {
			c.statePath = p
		}
	}
}

// WithWalkInterval sets how often protected folders are walked.
func WithWalkInterval(d time.Duration) Option {
	return func(c *Collector) {
		if d > 0 {
			c.walkEvery = d
		}
	}
}

func withClock(now func() time.Time) Option { return func(c *Collector) { c.now = now } }
func withVolumes(glob string) Option        { return func(c *Collector) { c.volumes = glob } }
func withSyncWalks() Option                 { return func(c *Collector) { c.syncWalks = true } }

// NewCollector creates the tripwire collector.
func NewCollector(hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname:  hostname,
		logger:    slog.Default(),
		builder:   metrics.NewBuilder().WithHostname(hostname),
		volumes:   sharesnap.DefaultVolumes,
		walkEvery: 15 * time.Minute,
		// A walk this long is stuck (a hung network mount) or the folder is
		// too big to judge on this interval; it is discarded.
		walkDeadline: 10 * time.Minute,
		now:          time.Now,
		results:      map[string]walkResult{},
		attempted:    map[string]time.Time{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Name returns the collector name.
func (c *Collector) Name() string { return "tripwire" }

// Enabled reports whether anything is configured to watch.
func (c *Collector) Enabled() bool { return len(c.canaries)+len(c.folders) > 0 }

// Close releases nothing.
func (c *Collector) Close() error { return nil }

type emitter struct {
	c   *Collector
	ts  time.Time
	out []metrics.Metric
}

func (e *emitter) gauge(name string, value float64, labels map[string]string) {
	m, err := e.c.builder.WithTimestamp(e.ts).GaugeWithLabels(name, value, labels)
	if err != nil {
		e.c.logger.Warn("failed to create gauge metric", "name", name, "error", err)
		return
	}
	e.out = append(e.out, m)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Collect checks every canary and reports the latest folder walks.
func (c *Collector) Collect(_ context.Context) ([]metrics.Metric, error) {
	e := &emitter{c: c, ts: c.now()}
	c.mu.Lock()
	if c.st == nil {
		c.st = loadState(c.statePath, c.logger)
	}
	c.mu.Unlock()

	if len(c.canaries) > 0 {
		c.checkCanaries(e)
	}
	if len(c.folders) > 0 {
		c.maybeWalk(e.ts)
		c.emitWalks(e)
	}
	c.mu.Lock()
	err := c.st.save(c.statePath)
	warn := err != nil && err.Error() != c.saveWarned
	if err != nil {
		c.saveWarned = err.Error()
	} else {
		c.saveWarned = ""
	}
	c.mu.Unlock()
	if warn {
		c.logger.Warn("tripwire baseline could not be saved; a restart would relearn it", "path", c.statePath, "error", err)
	}
	return e.out, nil
}

// fileHash hashes a canary without following a symlink: a canary replaced by
// a link has been tampered with.
func fileHash(path string) (sum string, size int64, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, errNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxCanaryBytes))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

var errNotRegular = errors.New("not a regular file")

// classify turns a read error into a canary state.
func classify(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return stateMissing
	case errors.Is(err, fs.ErrPermission):
		return stateUnreadable
	case errors.Is(err, errNotRegular):
		return stateModified
	default:
		return stateUnreadable
	}
}

func (c *Collector) checkCanaries(e *emitter) {
	tampered, unreadable, reported := 0, 0, 0
	snapBad, snapUnreadable := 0, 0
	for _, spec := range c.canaries {
		sum, size, err := fileHash(spec.path)
		st := stateIntact
		c.mu.Lock()
		base, known := c.st.Canaries[spec.path]
		// A pin is the expectation, here and for the snapshot copy, whatever
		// was learned before it was added. Only the hash is compared; the
		// size of a file that does not match is never learned.
		if spec.pinned != "" && (!known || base.SHA256 != spec.pinned) {
			first := e.ts
			if known {
				first = base.FirstSeen
			}
			base = canaryBaseline{SHA256: spec.pinned, Size: -1, FirstSeen: first}
			if sum == spec.pinned {
				base.Size = size
			}
			c.st.Canaries[spec.path] = base
			known = true
		}
		switch {
		case err != nil:
			st = classify(err)
		case !known:
			base = canaryBaseline{SHA256: sum, Size: size, FirstSeen: e.ts}
			c.st.Canaries[spec.path] = base
			known = true
		case sum != base.SHA256:
			st = stateModified
		}
		c.mu.Unlock()

		switch st {
		case stateMissing, stateModified:
			tampered++
		case stateUnreadable:
			unreadable++
		}
		if reported < maxReported {
			e.gauge("tripwire_canary_intact", b2f(st == stateIntact), map[string]string{"canary": spec.path, "state": st})
			reported++
		}

		if known {
			switch c.checkSnapshotCopy(e, spec.path, base) {
			case stateModified, stateMissing:
				snapBad++
			case stateUnreadable:
				snapUnreadable++
			}
		}
	}
	e.gauge("tripwire_canaries_watched", float64(len(c.canaries)), nil)
	e.gauge("tripwire_canaries_tampered", float64(tampered), nil)
	e.gauge("tripwire_canaries_unreadable", float64(unreadable), nil)
	if c.snapshotsInUse() {
		e.gauge("tripwire_canary_snapshots_bad", float64(snapBad), nil)
		e.gauge("tripwire_canary_snapshots_unreadable", float64(snapUnreadable), nil)
	}
}

func (c *Collector) snapshotsInUse() bool {
	shares, err := sharesnap.Shares(c.volumes)
	return err == nil && len(shares) > 0
}

// checkSnapshotCopy compares the canary's copy in its share's newest
// snapshot with the baseline. A snapshot taken before the canary was first
// seen cannot hold it and is not judged. Returns the copy's state, or "" when
// there is nothing to judge.
func (c *Collector) checkSnapshotCopy(e *emitter, path string, base canaryBaseline) string {
	share, rel, ok := sharesnap.Locate(path, c.volumes)
	if !ok {
		return ""
	}
	newest := share.Snapshots[0]
	if newest.Time.Before(base.FirstSeen) {
		return ""
	}
	sum, _, err := fileHash(filepath.Join(share.Dir, newest.Name, rel))
	st := stateIntact
	switch {
	case err != nil:
		st = classify(err)
	case sum != base.SHA256:
		st = stateModified
	}
	e.gauge("tripwire_canary_snapshot_intact", b2f(st == stateIntact), map[string]string{
		"canary": path, "share": share.Name, "snapshot": newest.Name, "state": st,
	})
	return st
}

// String helps log lines.
func (s canarySpec) String() string { return fmt.Sprintf("%s (pinned=%v)", s.path, s.pinned != "") }
