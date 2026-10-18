package k8s

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// coreReflectors gives c the six always-on reflectors without running them, so
// a test can mark them synced by hand.
func coreReflectors(c *Collector) {
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	c.pods = newReflector(nil, "/api/v1/pods", func(p Pod) string { return p.key() }, l, nil)
	c.nodes = newReflector(nil, "/api/v1/nodes", func(n Node) string { return n.key() }, l, nil)
	c.replicaSets = newReflector(nil, "/rs", func(r ReplicaSet) string { return r.key() }, l, nil)
	c.deployments = newReflector(nil, "/d", func(d Deployment) string { return d.key() }, l, nil)
	c.statefulSets = newReflector(nil, "/s", func(s StatefulSet) string { return s.key() }, l, nil)
	c.daemonSets = newReflector(nil, "/ds", func(d DaemonSet) string { return d.key() }, l, nil)
}

// The first Collect after a start waits for every core store, not only the
// first to answer. A reconcile sent before the pod store lists would carry no
// pod targets, and the server resolves open findings from that list.
func TestWaitForInitialSyncWaitsForEveryCoreStore(t *testing.T) {
	c := &Collector{}
	coreReflectors(c)
	c.nodes.markSynced()

	start := time.Now()
	c.waitForInitialSync(context.Background(), 300*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("returned after %v with only the node store synced", elapsed)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		c.pods.markSynced()
		c.replicaSets.markSynced()
		c.deployments.markSynced()
		c.statefulSets.markSynced()
		c.daemonSets.markSynced()
	}()
	start = time.Now()
	c.waitForInitialSync(context.Background(), 5*time.Second)
	if !c.coreSynced() {
		t.Fatal("returned before the core stores had synced")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("waited %v; should return promptly once synced", elapsed)
	}
}

func TestWaitForInitialSyncHonorsContextCancellation(t *testing.T) {
	c := &Collector{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	c.waitForInitialSync(ctx, 10*time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("ignored cancellation, waited %v", elapsed)
	}
}

func TestEnsureWatchersReportsFirstStartOnce(t *testing.T) {
	c := &Collector{}
	if c.ensureWatchers() {
		t.Fatal("no client configured: must not claim to have started watchers")
	}
}

// fakeAPIServer answers every list with one empty page (one Ready node for
// /api/v1/nodes), holds every watch open, and answers 403 on the paths in
// forbidden, as a cluster role missing one grant would.
func fakeAPIServer(t *testing.T, forbidden ...string) Config {
	t.Helper()
	deny := map[string]bool{}
	for _, p := range forbidden {
		deny[p] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case deny[r.URL.Path]:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"kind":"Status","reason":"Forbidden","message":"forbidden"}`)
		case r.URL.Path == "/version":
			_, _ = io.WriteString(w, `{"gitVersion":"v1.33.0"}`)
		case r.URL.Query().Get("watch") == "1":
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			<-r.Context().Done()
		case r.URL.Path == "/api/v1/nodes":
			_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"1"},"items":[`+
				`{"metadata":{"name":"node-a"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`)
		default:
			_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"1"},"items":[]}`)
		}
	}))
	t.Cleanup(srv.Close)

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{Host: srv.URL, TokenPath: tokenPath}
}

func collectOnce(t *testing.T, cfg Config) (map[string]float64, []metrics.Snapshot) {
	t.Helper()
	old := initialSyncTimeout
	initialSyncTimeout = 2 * time.Second
	t.Cleanup(func() { initialSyncTimeout = old })

	c := NewCollector("prod-cluster", WithConfig(cfg),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithCapabilities(Capabilities{}))
	t.Cleanup(func() { _ = c.Close() })
	ms, err := c.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, m := range ms {
		if len(m.Labels) == 1 { // just the host label: a cluster-wide series
			got[m.Name] = m.Value
		}
	}
	return got, c.Snapshots()
}

func hasSnapshot(snaps []metrics.Snapshot, typ string) bool {
	for _, s := range snaps {
		if s.Type == typ {
			return true
		}
	}
	return false
}

// Reachability is global but data is per store. With the pod list forbidden,
// the API reads as reachable while pod series stay absent, and no reconcile is
// sent until the pod store is current.
func TestStorePodListFailureIsAbsentNotZero(t *testing.T) {
	got, snaps := collectOnce(t, fakeAPIServer(t, "/api/v1/pods"))

	if got["k8s_api_reachable"] != 1 {
		t.Fatalf("the API answered every other list; reachable = %v", got["k8s_api_reachable"])
	}
	if got["k8s_nodes_total"] != 1 {
		t.Errorf("the node store is current and must still report, got %v", got["k8s_nodes_total"])
	}
	for _, name := range []string{"k8s_pods_running", "k8s_pods_failing", "k8s_restarts_total", "k8s_workloads_total"} {
		if v, ok := got[name]; ok {
			t.Errorf("%s = %v reported from a store that never synced", name, v)
		}
	}
	if hasSnapshot(snaps, metrics.SnapshotK8sClusterHealth) {
		t.Error("a reconcile was shipped without the pod store; it would resolve every open pod finding")
	}
}

// The same cluster with every grant present reports pods and reconciles on the
// first cycle.
func TestFirstCycleReconcilesOnceEveryStoreSynced(t *testing.T) {
	got, snaps := collectOnce(t, fakeAPIServer(t))

	if v, ok := got["k8s_pods_running"]; !ok || v != 0 {
		t.Errorf("k8s_pods_running = %v (present %v); want a real 0", v, ok)
	}
	if !hasSnapshot(snaps, metrics.SnapshotK8sClusterHealth) {
		t.Error("expected a reconcile on the first fully synced cycle")
	}
}

// An observation whose store was not current this cycle is carried forward,
// rather than read as "vanished while unhealthy, therefore recovered".
func TestDiffCarriesStaleObservationsForward(t *testing.T) {
	c := &Collector{lastObserved: map[string]observation{}}
	now := time.Now()
	broken := observation{key: "pod|ns|p", kind: "pod", namespace: "ns", name: "p",
		surface: true, reason: "CrashLoopBackOff"}
	c.diff([]observation{broken}, now, nil)

	stale := func(o observation) bool { return o.kind == "pod" }
	if tr := c.diff(nil, now.Add(time.Minute), stale); len(tr) != 0 {
		t.Fatalf("a stale pod store produced transitions %v", tr)
	}
	if _, ok := c.lastObserved[broken.key]; !ok {
		t.Fatal("the stale observation was dropped from the baseline")
	}
	if got := c.activeTargets(); len(got) != 1 || got[0] != "pod|ns|p" {
		t.Fatalf("active targets = %v; the open problem must stay open", got)
	}

	// Once the store is current again and the pod is gone, it recovers.
	if tr := c.diff(nil, now.Add(2*time.Minute), nil); len(tr) != 1 || tr[0]["state"] != "recovered" {
		t.Fatalf("expected one recovery, got %v", tr)
	}
}

// SetExcludedNamespaces runs on the config poll while skip() runs from the
// exporter scrapes and usage polls, which hold no lock. Run under -race.
func TestExcludedNamespacesAreSafeForConcurrentUse(t *testing.T) {
	c := NewCollector("prod-cluster")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 500 {
			c.SetExcludedNamespaces([]string{"a", "ns-" + itoa(i)})
		}
	}()
	for {
		select {
		case <-done:
			if !c.skip("a") || c.skip("b") || c.skip("") {
				t.Fatal("exclusions wrong after updates")
			}
			return
		default:
			_ = c.skip("a")
		}
	}
}
