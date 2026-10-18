package fim

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Real-time change detection.
//
// The periodic walk catches everything but only hourly. fsnotify closes the
// latency gap: a change under a watched directory is noticed within seconds,
// buffered, and re-checked on the next collection cycle, shipping as a change
// with detected="realtime". The watcher only nominates paths; the collector
// decides which are in scope (collector.go, inScope) and hashes them itself.
//
// Known gaps, all covered by the next periodic walk rather than here:
//   - Watches are capped (maxWatches). Directories past the cap are
//     periodic-only, and so is anything deeper than the walk's depth limit.
//   - A kernel event-queue overflow loses events. The watcher records the
//     overflow and the collector schedules a full walk on the next cycle.
//   - A directory created under a watched root is watched once its create
//     event is seen; files written into it before then produce no event.
//   - Other mounts beneath a root are not watched (nor walked), and a watched
//     directory that is renamed away keeps its watch under the old name.
//   - On kqueue platforms (macOS, the BSDs) fsnotify holds an open descriptor
//     for every file in a watched directory as well as the directory, so the
//     cap counts files there and the layer is off by default
//     (enable_fim_realtime).
//
// Watch descriptors are a bounded kernel resource, so the watcher caps how
// many it registers and leaves the rest to the periodic walk.

// maxWatches caps registered watches. Each inotify watch is a kernel resource;
// the default per-user limit is often 8192, shared across the whole system,
// so FIM takes a conservative slice. On kqueue it caps open descriptors.
const maxWatches = 2048

// kqueueWatches is true where fsnotify's backend opens one descriptor per
// file inside each watched directory.
var kqueueWatches = runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" ||
	runtime.GOOS == "netbsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "dragonfly"

// coalesceWindow debounces rapid repeated events for the same path. Editors
// and package managers touch a file several times in quick succession (write,
// chmod, rename); without debouncing that is several deltas for one logical
// change.
const coalesceWindow = 750 * time.Millisecond

// watcher wraps fsnotify with a bounded watch set and a coalescing buffer of
// pending real-time changes, drained by the collector each cycle.
type watcher struct {
	fsw    *fsnotify.Watcher
	logger *slog.Logger

	mu         sync.Mutex
	dirty      map[string]time.Time // path -> last event time (debounce)
	watchCount int
	overflow   bool
	stopped    bool
	stop       chan struct{}
}

// newWatcher registers recursive watches under the given roots and starts the
// event loop. It returns nil (real-time disabled, periodic-only) when fsnotify
// is unavailable, which is never fatal.
func newWatcher(roots []string, logger *slog.Logger) *watcher {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Warn("fsnotify unavailable; FIM runs periodic-only", "error", err)
		return nil
	}

	w := &watcher{
		fsw:    fsw,
		logger: logger,
		dirty:  map[string]time.Time{},
		stop:   make(chan struct{}),
	}

	w.mu.Lock()
	for _, root := range roots {
		w.addRecursive(root, 0)
	}
	full := w.watchCount >= maxWatches
	w.mu.Unlock()
	if full {
		logger.Warn("FIM watch limit reached; some paths are periodic-only",
			"limit", maxWatches, "hint", "narrow fim_roots or raise fs.inotify.max_user_watches")
	}

	go w.loop()
	return w
}

// addRecursive registers a watch on dir and every subdirectory, up to the cap
// and the walk's depth limit. Files are not watched individually: a directory
// watch reports events for its entries, which is how inotify is meant to be
// used. Callers hold w.mu.
func (w *watcher) addRecursive(path string, depth int) {
	if depth > maxWalkDepth || isPseudoFS(path) {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		return
	}

	// A single-file root: watch its parent directory instead, which also
	// sees the file being replaced by rename. Events for its siblings are
	// discarded by the collector's scope check.
	if info.Mode().IsRegular() {
		w.addOne(filepath.Dir(path))
		return
	}
	if !info.IsDir() {
		return
	}

	w.addOne(path)

	entries, err := os.ReadDir(path)
	if err != nil {
		return
	}
	for _, e := range entries {
		if w.watchCount >= maxWatches {
			return
		}
		// Do not descend symlinks, as in the walker.
		if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
			w.addRecursive(filepath.Join(path, e.Name()), depth+1)
		}
	}
}

// addOne watches one directory if its cost fits under maxWatches. Callers
// hold w.mu.
func (w *watcher) addOne(dir string) {
	cost := 1
	if kqueueWatches {
		if entries, err := os.ReadDir(dir); err == nil {
			cost += len(entries)
		}
	}
	if w.watchCount+cost > maxWatches {
		w.watchCount = maxWatches // full: stop trying further directories
		return
	}
	if err := w.fsw.Add(dir); err != nil {
		return
	}
	w.watchCount += cost
}

// loop consumes fsnotify events, recording each affected path for the next
// drain. A newly created directory under a watched root is itself watched, so
// a tree that grows is still covered.
func (w *watcher) loop() {
	for {
		select {
		case <-w.stop:
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.mu.Lock()
			w.dirty[ev.Name] = time.Now()
			w.mu.Unlock()

			if ev.Op&fsnotify.Create != 0 {
				if info, err := os.Lstat(ev.Name); err == nil &&
					info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
					w.mu.Lock()
					w.addOne(ev.Name)
					w.mu.Unlock()
				}
			}
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				w.mu.Lock()
				w.overflow = true
				w.mu.Unlock()
				w.logger.Warn("FIM real-time events overflowed; a full walk will reconcile")
				continue
			}
			w.logger.Debug("fsnotify error", "error", err)
		}
	}
}

// drainDirty returns the set of paths that changed and are past the coalesce
// window, clearing them. Paths still within the window are kept for the next
// drain so a burst of edits collapses to one delta.
func (w *watcher) drainDirty() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	var ready []string
	for path, t := range w.dirty {
		if now.Sub(t) >= coalesceWindow {
			ready = append(ready, path)
			delete(w.dirty, path)
		}
	}
	return ready
}

// requeue returns drained paths that could not be processed, so the next
// drain offers them again. A newer event for the same path wins.
func (w *watcher) requeue(paths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	past := time.Now().Add(-coalesceWindow)
	for _, p := range paths {
		if _, newer := w.dirty[p]; !newer {
			w.dirty[p] = past
		}
	}
}

// takeOverflow reports, and clears, whether events were lost since the last
// call.
func (w *watcher) takeOverflow() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	o := w.overflow
	w.overflow = false
	return o
}

// close stops the watcher.
func (w *watcher) close() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	w.stopped = true
	w.mu.Unlock()

	close(w.stop)
	_ = w.fsw.Close()
}
