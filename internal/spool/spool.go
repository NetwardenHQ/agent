// Package spool reads files that local producers (for example an OPNsense UI
// plugin) leave for the agent and turns them into snapshots for /agent/data.
//
// Layout under the spool directory (root-owned, not group/world writable):
//
//	events/*.jsonl   one event per line, delivered at least once
//	exposure.json    full-replace exposure report
//	identity.json    optional; only whitelisted keys are merged into device_identity
//
// Producers write "<name>.tmp" and rename(); *.tmp is never read. A file is
// deleted only after the post that carried all of its events got a 2xx
// (Batch.Ack). Nothing here invents values: unreadable or invalid input is
// skipped and counted, never replaced by a default.
package spool

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Limits. They mirror the public contract in docs/spool.md.
const (
	MaxEventsPerPost  = 500
	MaxExposureBytes  = 256 * 1024
	MaxIdentityBytes  = 16 * 1024
	MaxEventFileBytes = 10 * 1024 * 1024
	maxLineBytes      = 32 * 1024
	maxFilesListed    = 2000

	ExposureResendEvery = time.Hour

	maxTitle     = 200
	maxDetail    = 4000
	maxDedupeKey = 200
	maxLabels    = 32
)

var typeRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

// Event is one validated line of events/*.jsonl.
type Event struct {
	V          int               `json:"v"`
	Type       string            `json:"type"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Detail     string            `json:"detail,omitempty"`
	OccurredAt string            `json:"occurred_at"`
	DedupeKey  string            `json:"dedupe_key"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ParseEvent validates one line against the contract.
func ParseEvent(line []byte) (Event, error) {
	var e Event
	if err := json.Unmarshal(line, &e); err != nil {
		return Event{}, fmt.Errorf("not a valid event object: %w", err)
	}
	switch {
	case e.V != 1:
		return Event{}, fmt.Errorf("unsupported v=%d", e.V)
	case !typeRe.MatchString(e.Type):
		return Event{}, fmt.Errorf("invalid type %q", e.Type)
	case e.Severity != "info" && e.Severity != "warning" && e.Severity != "critical":
		return Event{}, fmt.Errorf("invalid severity %q", e.Severity)
	case e.DedupeKey == "" || utf8.RuneCountInString(e.DedupeKey) > maxDedupeKey:
		return Event{}, fmt.Errorf("dedupe_key must be 1-%d chars", maxDedupeKey)
	case e.Title == "" || utf8.RuneCountInString(e.Title) > maxTitle:
		return Event{}, fmt.Errorf("title must be 1-%d chars", maxTitle)
	case utf8.RuneCountInString(e.Detail) > maxDetail:
		return Event{}, fmt.Errorf("detail longer than %d chars", maxDetail)
	case len(e.Labels) > maxLabels:
		return Event{}, fmt.Errorf("more than %d labels", maxLabels)
	}
	if _, err := time.Parse(time.RFC3339, e.OccurredAt); err != nil {
		return Event{}, fmt.Errorf("occurred_at is not RFC3339: %w", err)
	}
	return e, nil
}

// Reader reads one spool directory. Safe for concurrent use.
type Reader struct {
	dir    string
	logger *slog.Logger
	uid    int
	now    func() time.Time

	// Lock order: mu, then wmu. warn() takes wmu and is called with mu
	// held; nothing takes mu while holding wmu.
	wmu    sync.Mutex // guards warned
	warned map[string]string

	mu      sync.Mutex
	offsets map[string]int64 // events file name -> bytes already delivered
	// skipCounted is, per events file, the end offset of the last invalid
	// line already counted in skipped. Lines are re-read every cycle until
	// acknowledged, and each invalid one must be counted once.
	skipCounted map[string]int64
	// stalled tracks a head event that did not fit an otherwise empty
	// events payload, so it can be skipped instead of blocking its file
	// forever.
	stalled stall
	pending map[string]pendingEntry // Pending() cache, by events file name
	skipped int                     // invalid event lines seen since start
	sent    int                     // events acknowledged since start

	exposureHash string
	exposureSent time.Time
}

// stall identifies the event at the head of the queue that keeps not fitting.
type stall struct {
	name   string
	offset int64
	cycles int
}

// maxStalledCycles is how many consecutive posts may lack room for the head
// event before it is skipped. A single tight post (a large metrics batch)
// must not drop a valid event; a budget that never grows must not stop the
// queue for good.
const maxStalledCycles = 10

// pendingEntry caches one file's pending-line count, valid while the file's
// size, mtime and delivered offset are unchanged.
type pendingEntry struct {
	size   int64
	mtime  time.Time
	offset int64
	count  int
}

// Option configures a Reader.
type Option func(*Reader)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(r *Reader) {
		if l != nil {
			r.logger = l
		}
	}
}

// WithOwnerUID overrides the required owner (default 0). Tests only.
func WithOwnerUID(uid int) Option { return func(r *Reader) { r.uid = uid } }

// WithClock overrides the clock. Tests only.
func WithClock(now func() time.Time) Option { return func(r *Reader) { r.now = now } }

// New creates a Reader. An empty dir yields a Reader that never returns data.
func New(dir string, opts ...Option) *Reader {
	r := &Reader{
		dir:         dir,
		logger:      slog.Default(),
		uid:         rootUID,
		now:         time.Now,
		offsets:     map[string]int64{},
		skipCounted: map[string]int64{},
		pending:     map[string]pendingEntry{},
		warned:      map[string]string{},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Skipped reports how many invalid event lines were discarded so far.
func (r *Reader) Skipped() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.skipped
}

func (r *Reader) warn(key, msg string, args ...any) {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if r.warned[key] == msg {
		return
	}
	r.warned[key] = msg
	r.logger.Warn(msg, args...)
}

// forgetWarnings drops warn() entries whose key starts with prefix and is not
// in keep, so a file that comes back with the same problem is reported again
// and the map does not grow with every file name ever seen.
func (r *Reader) forgetWarnings(prefix string, keep map[string]bool) {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	for k := range r.warned {
		if strings.HasPrefix(k, prefix) && !keep[k] {
			delete(r.warned, k)
		}
	}
}

// Every check below is made on the object that is then used: a directory
// becomes an os.Root (which refuses to resolve outside itself), and a file is
// opened first and then checked through fstat on the open descriptor. A
// check by path followed by an open by path could be answered by one file
// and read from another.

// openSpool opens the spool directory as a root after checking it and every
// directory above it.
func (r *Reader) openSpool() (*os.Root, bool) {
	key := "dir:" + r.dir
	abs, err := filepath.Abs(r.dir)
	if err != nil {
		r.warn(key, "spool directory unusable", "dir", r.dir, "error", err)
		return nil, false
	}
	// Resolve symlinks above the spool directory (for example /var ->
	// /private/var), never the spool directory itself.
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		if !os.IsNotExist(err) {
			r.warn(key, "spool directory unreadable", "dir", r.dir, "error", err)
		}
		return nil, false
	}
	if err := checkParents(parent, r.uid); err != nil {
		r.warn(key, "a directory above the spool is not trusted; spool ignored", "dir", r.dir, "reason", err.Error())
		return nil, false
	}
	path := filepath.Join(parent, filepath.Base(abs))
	lst, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.warn(key, "spool directory unreadable", "dir", r.dir, "error", err)
		}
		return nil, false
	}
	if lst.Mode()&os.ModeSymlink != 0 || !lst.IsDir() {
		r.warn(key, "spool path is not a plain directory; spool ignored", "dir", r.dir)
		return nil, false
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		r.warn(key, "spool directory unreadable", "dir", r.dir, "error", err)
		return nil, false
	}
	if !r.trustedRoot(root, lst, key, r.dir) {
		root.Close()
		return nil, false
	}
	return root, true
}

// openEvents opens the events subdirectory of an open spool root.
func (r *Reader) openEvents(spool *os.Root) (*os.Root, bool) {
	name := filepath.Join(r.dir, "events")
	key := "dir:" + name
	lst, err := spool.Lstat("events")
	if err != nil {
		if !os.IsNotExist(err) {
			r.warn(key, "spool directory unreadable", "dir", name, "error", err)
		}
		return nil, false
	}
	if lst.Mode()&os.ModeSymlink != 0 || !lst.IsDir() {
		r.warn(key, "spool path is not a plain directory; spool ignored", "dir", name)
		return nil, false
	}
	ev, err := spool.OpenRoot("events")
	if err != nil {
		r.warn(key, "spool directory unreadable", "dir", name, "error", err)
		return nil, false
	}
	if !r.trustedRoot(ev, lst, key, name) {
		ev.Close()
		return nil, false
	}
	return ev, true
}

// trustedRoot verifies, through a descriptor, that root is the directory
// lst described and that it is trusted.
func (r *Reader) trustedRoot(root *os.Root, lst os.FileInfo, key, name string) bool {
	d, err := root.Open(".")
	if err != nil {
		r.warn(key, "spool directory unreadable", "dir", name, "error", err)
		return false
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil || !os.SameFile(fi, lst) {
		r.warn(key, "spool directory changed while being opened; spool ignored", "dir", name)
		return false
	}
	if err := checkTrusted(d, fi, r.uid); err != nil {
		r.warn(key, "spool directory is not trusted; spool ignored", "dir", name, "reason", err.Error())
		return false
	}
	return true
}

// openTrusted opens a regular, non-symlink file in root and checks the open
// file's owner, mode and size (at most max). The caller closes it.
func (r *Reader) openTrusted(root *os.Root, name, display string, max int64) (*os.File, os.FileInfo, bool) {
	key := "file:" + display
	lst, err := root.Lstat(name)
	if err != nil {
		return nil, nil, false
	}
	if !lst.Mode().IsRegular() {
		r.warn(key, "spool entry is not a regular file; ignored", "path", display)
		return nil, nil, false
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, false
	}
	fi, err := f.Stat()
	if err != nil || !os.SameFile(fi, lst) || !fi.Mode().IsRegular() {
		f.Close()
		r.warn(key, "spool file changed while being opened; ignored", "path", display)
		return nil, nil, false
	}
	if err := checkTrusted(f, fi, r.uid); err != nil {
		f.Close()
		r.warn(key, "spool file is not trusted; ignored", "path", display, "reason", err.Error())
		return nil, nil, false
	}
	if fi.Size() > max {
		f.Close()
		r.warn(key, "spool file exceeds size cap; ignored", "path", display, "size", fi.Size(), "cap", max)
		return nil, nil, false
	}
	return f, fi, true
}

// readSmall reads a trusted JSON file fully (bounded by max).
func (r *Reader) readSmall(name string, max int64) ([]byte, bool) {
	root, ok := r.openSpool()
	if !ok {
		return nil, false
	}
	defer root.Close()
	f, _, ok := r.openTrusted(root, name, filepath.Join(r.dir, name), max)
	if !ok {
		return nil, false
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, false
	}
	return raw, true
}

// Identity returns the allowed keys of identity.json (only unisense_version)
// for merging into device_identity. It returns nil when the file is absent or
// carries none of them.
func (r *Reader) Identity() map[string]any {
	if r == nil || r.dir == "" {
		return nil
	}
	raw, ok := r.readSmall("identity.json", MaxIdentityBytes)
	if !ok {
		return nil
	}
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		r.warn("identity", "identity.json is not valid JSON; ignored", "error", err)
		return nil
	}
	out := map[string]any{}
	if v, ok := in["unisense_version"].(string); ok && v != "" && len(v) <= 64 {
		out["unisense_version"] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Batch is what one cycle may send. Ack must be called only after the post
// carrying Snapshots returned 2xx; until then nothing is consumed.
type Batch struct {
	Snapshots []metrics.Snapshot
	Ack       func()
}

type fileProgress struct {
	name   string
	offset int64 // byte offset after the last line consumed
	done   bool  // reached EOF
}

// Next returns up to maxSnaps snapshots whose JSON should fit in maxBytes.
// Exposure has priority over events; events are deferred first when space is
// short. Both are re-offered on every call until acknowledged.
func (r *Reader) Next(maxSnaps, maxBytes int) Batch {
	if r == nil || r.dir == "" || maxSnaps <= 0 {
		return Batch{Ack: func() {}}
	}
	var acks []func()
	var snaps []metrics.Snapshot

	if s, used, ack, ok := r.exposure(maxBytes); ok {
		snaps = append(snaps, s)
		maxBytes -= used
		maxSnaps--
		acks = append(acks, ack)
	}
	if maxSnaps > 0 {
		if s, ack, ok := r.events(maxBytes); ok {
			snaps = append(snaps, s)
			acks = append(acks, ack)
		}
	}
	return Batch{Snapshots: snaps, Ack: func() {
		for _, a := range acks {
			a()
		}
	}}
}

const snapshotOverhead = 64

func (r *Reader) exposure(maxBytes int) (metrics.Snapshot, int, func(), bool) {
	raw, ok := r.readSmall("exposure.json", MaxExposureBytes)
	if !ok {
		return metrics.Snapshot{}, 0, nil, false
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		r.warn("exposure", "exposure.json is not a valid JSON object; ignored")
		return metrics.Snapshot{}, 0, nil, false
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	size := len(raw) + snapshotOverhead

	r.mu.Lock()
	due := hash != r.exposureHash || r.now().Sub(r.exposureSent) >= ExposureResendEvery
	r.mu.Unlock()
	if !due {
		return metrics.Snapshot{}, 0, nil, false
	}
	if size > maxBytes {
		// Deferred rather than dropped: exposure is a full-replace report, so
		// there is nothing to advance past, and events get the whole budget
		// meanwhile. Logged once per report.
		r.warn("exposure-size", "exposure.json does not fit this post; deferred",
			"hash", hash[:12], "size", size, "budget", maxBytes)
		return metrics.Snapshot{}, 0, nil, false
	}
	sentAt := r.now()
	return metrics.Snapshot{Type: metrics.SnapshotNetworkExposure, Payload: obj}, size, func() {
		r.mu.Lock()
		r.exposureHash, r.exposureSent = hash, sentAt
		r.mu.Unlock()
	}, true
}

// eventNames lists the deliverable file names in an open events root.
func eventNames(ev *os.Root) ([]string, error) {
	d, err := ev.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".jsonl") && !strings.HasPrefix(n, ".") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

// forgetVanishedLocked drops per-file state for files no longer listed.
func (r *Reader) forgetVanishedLocked(names []string) {
	present := make(map[string]bool, len(names))
	keep := make(map[string]bool, len(names))
	prefix := "file:" + filepath.Join(r.dir, "events") + string(filepath.Separator)
	for _, n := range names {
		present[n] = true
		keep[prefix+n] = true
	}
	for n := range r.offsets {
		if !present[n] {
			delete(r.offsets, n)
		}
	}
	for n := range r.skipCounted {
		if !present[n] {
			delete(r.skipCounted, n)
		}
	}
	for n := range r.pending {
		if !present[n] {
			delete(r.pending, n)
		}
	}
	r.forgetWarnings(prefix, keep)
}

func (r *Reader) events(maxBytes int) (metrics.Snapshot, func(), bool) {
	spool, ok := r.openSpool()
	if !ok {
		return metrics.Snapshot{}, nil, false
	}
	defer spool.Close()
	ev, ok := r.openEvents(spool)
	if !ok {
		return metrics.Snapshot{}, nil, false
	}
	defer ev.Close()
	names, err := eventNames(ev)
	if err != nil {
		return metrics.Snapshot{}, nil, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.forgetVanishedLocked(names)
	if len(names) > maxFilesListed {
		names = names[:maxFilesListed]
	}

	var (
		events   []Event
		progress []fileProgress
		bytes    = snapshotOverhead + len(`{"events":[]}`)
		full     bool
	)
	evDir := filepath.Join(r.dir, "events")
	for _, n := range names {
		if full {
			break
		}
		f, fi, ok := r.openTrusted(ev, n, filepath.Join(evDir, n), MaxEventFileBytes)
		if !ok {
			continue
		}
		start := r.offsets[n]
		if start > fi.Size() {
			start = 0 // file was replaced by a shorter one
			delete(r.skipCounted, n)
		}
		fp := fileProgress{name: n, offset: start}
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			f.Close()
			continue
		}
		br := bufio.NewReaderSize(f, 64*1024)
		for {
			line, nb, tooLong, err := readLine(br)
			if nb == 0 && err != nil {
				fp.done = err == io.EOF
				break
			}
			consumed := fp.offset + int64(nb)
			trimmed := strings.TrimSpace(string(line))
			if trimmed == "" && !tooLong {
				fp.offset = consumed
			} else {
				var e Event
				var perr error
				if tooLong {
					perr = fmt.Errorf("line longer than %d bytes", maxLineBytes)
				} else {
					e, perr = ParseEvent([]byte(trimmed))
				}
				if perr != nil {
					r.countSkippedLocked(n, consumed)
					r.logger.Debug("invalid spool event skipped", "file", n, "error", perr)
					fp.offset = consumed
				} else {
					enc, _ := json.Marshal(e)
					if len(events) >= MaxEventsPerPost || bytes+len(enc)+1 > maxBytes {
						if len(events) == 0 && r.stalledLocked(n, fp.offset, len(enc), maxBytes) {
							// Skipped after maxStalledCycles; see stalledLocked.
							r.countSkippedLocked(n, consumed)
							fp.offset = consumed
							continue
						}
						full = true
						break // leave this line for the next cycle
					}
					events = append(events, e)
					bytes += len(enc) + 1
					fp.offset = consumed
				}
			}
			if err != nil {
				fp.done = err == io.EOF
				break
			}
		}
		f.Close()
		progress = append(progress, fp)
	}
	if len(events) > 0 {
		r.stalled = stall{}
	}

	if len(events) == 0 {
		// Nothing deliverable. Files that are fully read hold only invalid or
		// blank lines; there is no post to wait for, so they can go.
		for _, fp := range progress {
			if fp.done {
				r.removeLocked(ev, fp.name)
			} else {
				r.offsets[fp.name] = fp.offset
			}
		}
		return metrics.Snapshot{}, nil, false
	}

	snap := metrics.Snapshot{Type: metrics.SnapshotEvents, Payload: map[string]any{"events": events}}
	count := len(events)
	return snap, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.sent += count
		var ev *os.Root
		for _, fp := range progress {
			if !fp.done {
				r.offsets[fp.name] = fp.offset
				continue
			}
			if ev == nil {
				spool, ok := r.openSpool()
				if !ok {
					break
				}
				defer spool.Close()
				if ev, ok = r.openEvents(spool); !ok {
					break
				}
				defer ev.Close()
			}
			r.removeLocked(ev, fp.name)
		}
	}, true
}

// countSkippedLocked counts the invalid line ending at end once, however
// often it is re-read before its file is acknowledged.
func (r *Reader) countSkippedLocked(name string, end int64) {
	if end > r.skipCounted[name] {
		r.skipped++
		r.skipCounted[name] = end
	}
}

// stalledLocked is called when the event at (name, offset) is first in line
// and still does not fit the post. It reports whether to skip it now: after
// maxStalledCycles consecutive posts without room. The first deferral and the
// skip are logged.
func (r *Reader) stalledLocked(name string, offset int64, size, budget int) bool {
	if r.stalled.name == name && r.stalled.offset == offset {
		r.stalled.cycles++
	} else {
		r.stalled = stall{name: name, offset: offset, cycles: 1}
	}
	if r.stalled.cycles >= maxStalledCycles {
		r.logger.Warn("spool event never fit a post; skipped",
			"file", name, "offset", offset, "size", size, "budget", budget, "posts", r.stalled.cycles)
		r.stalled = stall{}
		return true
	}
	r.warn(fmt.Sprintf("stall:%s:%d", name, offset), "spool event does not fit this post; deferred",
		"file", name, "offset", offset, "size", size, "budget", budget)
	return false
}

// removeLocked deletes a delivered file (never a symlink) through the events
// root and forgets its state.
func (r *Reader) removeLocked(ev *os.Root, name string) {
	delete(r.offsets, name)
	delete(r.skipCounted, name)
	delete(r.pending, name)
	if fi, err := ev.Lstat(name); err == nil && fi.Mode().IsRegular() {
		if err := ev.Remove(name); err != nil {
			r.logger.Warn("could not delete delivered spool file", "path", filepath.Join(r.dir, "events", name), "error", err)
		}
	}
}

// readLine reads one line of at most maxLineBytes. n is the number of bytes
// consumed from the stream including the newline. When the line is longer the
// remainder is discarded and tooLong is set.
func readLine(br *bufio.Reader) (line []byte, n int, tooLong bool, err error) {
	for {
		chunk, e := br.ReadSlice('\n')
		n += len(chunk)
		if !tooLong {
			if len(line)+len(chunk) > maxLineBytes {
				tooLong = true
				line = nil
			} else {
				line = append(line, chunk...)
			}
		}
		switch e {
		case nil:
			return line, n, tooLong, nil
		case bufio.ErrBufferFull:
			continue
		default:
			return line, n, tooLong, e
		}
	}
}

// EnsureDirs creates the spool directory and its events subdirectory when
// missing, private to the agent: mode 0700 on POSIX (root-owned when run as
// root), a protected SYSTEM+Administrators DACL on Windows. Existing
// directories are left exactly as they are: the trust checks decide later
// whether they may be read.
func (r *Reader) EnsureDirs() error {
	if r == nil || r.dir == "" {
		return nil
	}
	for _, d := range []string{r.dir, filepath.Join(r.dir, "events")} {
		if _, err := os.Lstat(d); err == nil {
			continue
		}
		if err := mkdirPrivate(d); err != nil {
			return err
		}
	}
	return nil
}

// SentTotal is the number of events acknowledged since the Reader was made.
func (r *Reader) SentTotal() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sent
}

// Pending counts the non-blank lines not yet delivered in trusted event
// files. It is a count of lines, so an invalid line is included until the
// next read discards it.
//
// It runs after every post, so a file is only re-read when its size, mtime
// or delivered offset changed since the last count, and never under r.mu.
func (r *Reader) Pending() int {
	if r == nil || r.dir == "" {
		return 0
	}
	spool, ok := r.openSpool()
	if !ok {
		return 0
	}
	defer spool.Close()
	ev, ok := r.openEvents(spool)
	if !ok {
		return 0
	}
	defer ev.Close()
	names, err := eventNames(ev)
	if err != nil {
		return 0
	}

	r.mu.Lock()
	offsets := make(map[string]int64, len(names))
	cached := make(map[string]pendingEntry, len(names))
	for _, n := range names {
		offsets[n] = r.offsets[n]
		if c, ok := r.pending[n]; ok {
			cached[n] = c
		}
	}
	r.mu.Unlock()

	total := 0
	fresh := map[string]pendingEntry{}
	evDir := filepath.Join(r.dir, "events")
	for _, n := range names {
		f, fi, ok := r.openTrusted(ev, n, filepath.Join(evDir, n), MaxEventFileBytes)
		if !ok {
			continue
		}
		off := offsets[n]
		if off > fi.Size() {
			off = 0
		}
		if c, ok := cached[n]; ok && c.size == fi.Size() && c.mtime.Equal(fi.ModTime()) && c.offset == off {
			f.Close()
			total += c.count
			continue
		}
		count, err := countPending(f, off)
		f.Close()
		if err != nil {
			r.warn("pending:"+n, "could not count pending spool events", "file", n, "error", err)
			continue
		}
		fresh[n] = pendingEntry{size: fi.Size(), mtime: fi.ModTime(), offset: off, count: count}
		total += count
	}

	r.mu.Lock()
	for n, e := range fresh {
		r.pending[n] = e
	}
	r.mu.Unlock()
	return total
}

// countPending counts the lines after off that a read would consider: every
// non-blank line, and every over-long one.
func countPending(f *os.File, off int64) (int, error) {
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	br := bufio.NewReaderSize(f, 64*1024)
	n := 0
	for {
		line, nb, tooLong, err := readLine(br)
		if nb > 0 && (tooLong || strings.TrimSpace(string(line)) != "") {
			n++
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}
