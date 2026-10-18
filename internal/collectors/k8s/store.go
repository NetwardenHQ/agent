package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// store is a thread-safe in-memory cache of one resource kind, kept current by
// a reflector. Collect reads a consistent snapshot of it each cycle.
type store[T any] struct {
	mu    sync.RWMutex
	items map[string]T
}

func newStore[T any]() *store[T] { return &store[T]{items: map[string]T{}} }

func (s *store[T]) replace(items map[string]T) {
	s.mu.Lock()
	s.items = items
	s.mu.Unlock()
}

func (s *store[T]) put(k string, v T) {
	s.mu.Lock()
	s.items[k] = v
	s.mu.Unlock()
}

func (s *store[T]) delete(k string) {
	s.mu.Lock()
	delete(s.items, k)
	s.mu.Unlock()
}

func (s *store[T]) get(k string) (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.items[k]
	return v, ok
}

func (s *store[T]) list() []T {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]T, 0, len(s.items))
	for _, v := range s.items {
		out = append(out, v)
	}
	return out
}

// reflector maintains a store by the standard Kubernetes list-then-watch
// pattern: list to seed the cache and obtain a resourceVersion, then watch from
// that version for incremental changes. When a watch ends normally (the server
// closes it, the connection drops, the request times out) it re-watches from the
// newest resourceVersion it has seen, so a healthy store is listed once and then
// only streamed. It re-lists only when the server says that version is gone (an
// ERROR event, typically 410) or rejects the watch request outright. It is a
// minimal informer that avoids a client-go dependency.
type reflector[T any] struct {
	client *Client
	path   string
	keyOf  func(T) string
	store  *store[T]
	logger *slog.Logger

	// onSync is invoked after every successful list, every opened watch and
	// every watch event, so the collector can treat "heard from recently" as
	// "API reachable" without a separate probe.
	onSync func()

	// syncedAt is when this store was last known to be current (unix nanos; 0
	// until the first list). Reachability is a property of the API server, but
	// freshness is per store: the pod list can fail (RBAC, size) while every
	// other resource syncs, and that must not be reported as zero pods.
	syncedAt atomic.Int64
	// watching is true while a watch stream is open. An open stream keeps the
	// store current even when the resource is so quiet that nothing, not even
	// a bookmark, arrives for several collection intervals.
	watching atomic.Bool
}

func newReflector[T any](client *Client, path string, keyOf func(T) string, logger *slog.Logger, onSync func()) *reflector[T] {
	return &reflector[T]{
		client: client,
		path:   path,
		keyOf:  keyOf,
		store:  newStore[T](),
		logger: logger,
		onSync: onSync,
	}
}

// markSynced records that the store is current as of now.
func (r *reflector[T]) markSynced() {
	r.syncedAt.Store(time.Now().UnixNano())
	if r.onSync != nil {
		r.onSync()
	}
}

// lastSynced returns when the store was last known to be current, or the zero
// time if it never has been. Safe on a nil reflector (watchers not started).
func (r *reflector[T]) lastSynced() time.Time {
	if r == nil {
		return time.Time{}
	}
	ns := r.syncedAt.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// current reports whether the store can be trusted at now: it has listed, and
// either a watch is open on it or it heard from the API server within window.
// Safe on a nil reflector.
func (r *reflector[T]) current(now time.Time, window time.Duration) bool {
	at := r.lastSynced()
	if at.IsZero() {
		return false
	}
	return r.watching.Load() || now.Sub(at) < window
}

// Backoff bounds. Variables so tests can run the loop at millisecond scale.
var (
	reflectorBackoffMin = time.Second
	reflectorBackoffMax = 30 * time.Second
)

// quickWatchFailure is how short a watch must be, with no event delivered, to
// count as a failure rather than a normal end. A watch the server closes after
// its 5–10 minute lifetime re-opens at once; one that dies in under a second,
// over and over (an overloaded API server, a proxy that drops streams), backs
// off instead of hammering the server in a tight loop.
const quickWatchFailure = 5 * time.Second

// errResync means the watch cannot be resumed and the store must be re-listed.
var errResync = errors.New("watch requires a re-list")

// run drives the list-watch loop until ctx is canceled. Failures are logged and
// retried with capped backoff.
func (r *reflector[T]) run(ctx context.Context) {
	backoff := reflectorBackoffMin
	rv := ""
	for ctx.Err() == nil {
		if rv == "" {
			listed, err := r.listAll(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				r.logger.Warn("k8s reflector list failed", "path", r.path, "error", err)
				backoff = sleepBackoff(ctx, backoff)
				continue
			}
			rv = listed
		}

		started := time.Now()
		latest, events, err := r.watch(ctx, rv)
		if ctx.Err() != nil {
			return
		}
		if latest != "" {
			rv = latest
		}
		var status *apiStatusError
		if errors.Is(err, errResync) || errors.As(err, &status) {
			// The server rejected this resourceVersion (or the request): only a
			// fresh list can produce a consistent store again.
			r.logger.Debug("k8s watch needs a re-list", "path", r.path, "error", err)
			rv = ""
		} else if err != nil {
			r.logger.Debug("k8s watch ended; resuming", "path", r.path, "resource_version", rv, "error", err)
		}

		// Only a watch that delivered an event or stayed open resets the
		// backoff. A successful list does not, because a list followed by an
		// instant watch failure is the loop the backoff exists to slow down.
		if events == 0 && time.Since(started) < quickWatchFailure {
			backoff = sleepBackoff(ctx, backoff)
		} else {
			backoff = reflectorBackoffMin
		}
	}
}

func (r *reflector[T]) listAll(ctx context.Context) (string, error) {
	var list genericList[T]
	if err := r.client.List(ctx, r.path, &list); err != nil {
		return "", err
	}
	items := make(map[string]T, len(list.Items))
	for _, it := range list.Items {
		items[r.keyOf(it)] = it
	}
	r.store.replace(items)
	r.markSynced()
	return list.Metadata.ResourceVersion, nil
}

// watch streams events from rv into the store until the stream ends. It
// returns the newest resourceVersion seen (empty if none), how many events
// arrived, and why the stream ended; errResync means rv can no longer be
// resumed from.
func (r *reflector[T]) watch(ctx context.Context, rv string) (string, int, error) {
	stream, err := r.client.Watch(ctx, r.path, rv)
	if err != nil {
		return "", 0, err
	}
	defer stream.Close()
	// The server accepted a watch from our resourceVersion, so the store is
	// current as of now, and stays so while the stream is open.
	r.markSynced()
	r.watching.Store(true)
	defer r.watching.Store(false)

	latest := ""
	events := 0
	for {
		ev, err := stream.Next()
		if err != nil {
			return latest, events, err // EOF, timeout or decode error → resume
		}
		events++
		// Any event, including a BOOKMARK carrying only a resourceVersion,
		// proves the connection to the API server is alive. Bookmarks are
		// requested so an idle cluster still produces this heartbeat.
		r.markSynced()

		switch ev.Type {
		case WatchAdded, WatchModified:
			var obj T
			if json.Unmarshal(ev.Object, &obj) == nil {
				r.store.put(r.keyOf(obj), obj)
			}
		case WatchDeleted:
			var obj T
			if json.Unmarshal(ev.Object, &obj) == nil {
				r.store.delete(r.keyOf(obj))
			}
		case WatchError:
			// Typically 410 Gone: the resourceVersion is too old to resume from.
			return "", events, fmt.Errorf("%w: error event on %s: %s", errResync, r.path, watchErrorMessage(ev.Object))
		}

		// Every object event, and every BOOKMARK, carries the resourceVersion
		// to resume from. Decoded separately because T has no common accessor;
		// the struct is tiny and encoding/json skips everything else.
		var meta struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if json.Unmarshal(ev.Object, &meta) == nil && meta.Metadata.ResourceVersion != "" {
			latest = meta.Metadata.ResourceVersion
		}
	}
}

// watchErrorMessage extracts the Status message an ERROR event carries.
func watchErrorMessage(obj json.RawMessage) string {
	var s struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(obj, &s) != nil {
		return "undecodable status"
	}
	return fmt.Sprintf("%d %s", s.Code, s.Message)
}

// sleepBackoff sleeps for the current backoff (respecting ctx) and returns the
// next value, doubling up to reflectorBackoffMax.
func sleepBackoff(ctx context.Context, cur time.Duration) time.Duration {
	t := time.NewTimer(cur)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	return min(cur*2, reflectorBackoffMax)
}
