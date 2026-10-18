package k8s

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Events on an established watch, bookmarks included, refresh liveness, so
// k8s_api_reachable stays 1 on an idle cluster without a re-list.
func TestWatchEventKeepsReachabilityFresh(t *testing.T) {
	var listed atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "1" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// A BOOKMARK carries only a resourceVersion advance, which is all an
			// idle cluster produces.
			_, _ = io.WriteString(w, `{"type":"BOOKMARK","object":{}}`+"\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			<-r.Context().Done()
			return
		}
		listed.Store(true)
		_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"1"},"items":[]}`)
	}))
	defer srv.Close()

	// The client reads the SA token fresh on every request (projected tokens
	// rotate), so the test needs a real file on disk.
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &Client{
		cfg:    Config{Host: srv.URL, TokenPath: tokenPath},
		base:   srv.URL,
		list:   srv.Client(),
		stream: srv.Client(),
	}

	var syncs atomic.Int64
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := newReflector(client, "/api/v1/pods",
		func(p Pod) string { return p.key() }, logger, func() { syncs.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx)

	// One sync for the list, then at least one more for the bookmark.
	deadline := time.Now().Add(5 * time.Second)
	for syncs.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}

	if !listed.Load() {
		t.Fatal("reflector never listed")
	}
	if got := syncs.Load(); got < 2 {
		t.Fatalf("onSync fired %d time(s); a watch BOOKMARK must refresh liveness too", got)
	}
}

// testClient points a Client at srv with a real token file on disk.
func testClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Client{
		cfg:    Config{Host: srv.URL, TokenPath: tokenPath},
		base:   srv.URL,
		list:   srv.Client(),
		stream: srv.Client(),
	}
}

func fastBackoff(t *testing.T) {
	t.Helper()
	oldMin, oldMax := reflectorBackoffMin, reflectorBackoffMax
	reflectorBackoffMin, reflectorBackoffMax = 20*time.Millisecond, 2*time.Second
	t.Cleanup(func() { reflectorBackoffMin, reflectorBackoffMax = oldMin, oldMax })
}

// A watch that ends normally resumes from the newest resourceVersion its
// events carried, bookmarks included, without re-listing. Re-listing every pod
// each time a watch times out is the load the watch API exists to avoid.
func TestWatchResumesFromLatestResourceVersion(t *testing.T) {
	fastBackoff(t)
	var lists, watches atomic.Int64
	resumedFrom := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "1" {
			lists.Add(1)
			_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"10"},"items":[]}`)
			return
		}
		switch watches.Add(1) {
		case 1:
			if got := r.URL.Query().Get("resourceVersion"); got != "10" {
				t.Errorf("first watch from %q, want the list's 10", got)
			}
			_, _ = io.WriteString(w,
				`{"type":"ADDED","object":{"metadata":{"namespace":"a","name":"p","resourceVersion":"12"}}}`+"\n"+
					`{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"15"}}}`+"\n")
			// Stream ends: the server's timeoutSeconds elapsed.
		default:
			resumedFrom <- r.URL.Query().Get("resourceVersion")
			<-r.Context().Done()
		}
	}))
	defer srv.Close()

	r := newReflector(testClient(t, srv), "/api/v1/pods",
		func(p Pod) string { return p.key() }, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx)

	select {
	case rv := <-resumedFrom:
		if rv != "15" {
			t.Fatalf("second watch resumed from %q, want the bookmark's 15", rv)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reflector never opened a second watch")
	}
	if got := lists.Load(); got != 1 {
		t.Fatalf("listed %d times; an ended watch must resume, not re-list", got)
	}
	if _, ok := r.store.get("pod|a|p"); !ok {
		t.Fatal("the ADDED event did not reach the store")
	}
}

// An ERROR event (410 Gone: the version was compacted away) can only be
// recovered from by re-listing.
func TestWatchErrorEventForcesRelist(t *testing.T) {
	fastBackoff(t)
	var lists, watches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "1" {
			lists.Add(1)
			_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"10"},"items":[]}`)
			return
		}
		if watches.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired","message":"too old resource version"}}`+"\n")
			return
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	r := newReflector(testClient(t, srv), "/api/v1/pods",
		func(p Pod) string { return p.key() }, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for lists.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := lists.Load(); got != 2 {
		t.Fatalf("listed %d times; a 410 ERROR event must trigger exactly one re-list", got)
	}
}

// A watch that dies instantly, over and over, backs off even though each
// preceding list succeeded.
func TestQuicklyFailingWatchBacksOff(t *testing.T) {
	fastBackoff(t)
	var lists, watches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "1" {
			lists.Add(1)
			_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"10"},"items":[]}`)
			return
		}
		watches.Add(1) // 200 and an immediately closed, empty stream
	}))
	defer srv.Close()

	r := newReflector(testClient(t, srv), "/api/v1/pods",
		func(p Pod) string { return p.key() }, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	r.run(ctx)

	// 20, 40, 80, 160, 320 ms: about five attempts fit in 700ms. Without the
	// growth it is one every 20ms, around thirty.
	if got := watches.Load(); got > 8 {
		t.Fatalf("%d watch attempts in 700ms; a watch failing instantly must back off", got)
	}
	if got := lists.Load(); got != 1 {
		t.Fatalf("listed %d times; an empty, closed stream is resumed, not re-listed", got)
	}
}
