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

// A watch whose connection has gone silent (no events, no EOF) still ends, so
// the reflector opens a new one instead of serving a stale store. The new watch
// resumes from the resourceVersion already held; a dead connection does not
// call for a re-list.
func TestSilentWatchEndsAndReflectorRewatches(t *testing.T) {
	oldMin, oldMax, oldGrace := watchTimeoutMin, watchTimeoutMax, watchTimeoutGrace
	watchTimeoutMin, watchTimeoutMax, watchTimeoutGrace = 200*time.Millisecond, 201*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { watchTimeoutMin, watchTimeoutMax, watchTimeoutGrace = oldMin, oldMax, oldGrace })

	var lists, watches atomic.Int64
	var sawTimeoutParam atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "1" {
			watches.Add(1)
			if r.URL.Query().Get("timeoutSeconds") != "" {
				sawTimeoutParam.Store(true)
			}
			// A server that ignores timeoutSeconds and never sends anything:
			// the worst case, indistinguishable from a dead connection.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			<-r.Context().Done()
			return
		}
		lists.Add(1)
		_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"1"},"items":[]}`)
	}))
	defer srv.Close()

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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := newReflector(client, "/api/v1/pods", func(p Pod) string { return p.key() }, logger, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for watches.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !sawTimeoutParam.Load() {
		t.Fatal("watch request must carry timeoutSeconds so the API server ends it")
	}
	if got := watches.Load(); got < 2 {
		t.Fatalf("reflector opened %d watch(es); a silent watch must expire client-side and be replaced", got)
	}
	if got := lists.Load(); got != 1 {
		t.Fatalf("reflector listed %d times; an expired watch resumes, it does not re-list", got)
	}
}
