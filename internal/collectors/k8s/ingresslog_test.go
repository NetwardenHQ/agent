package k8s

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/spool"
)

func controllerPod(name string, started time.Time) Pod {
	p := Pod{}
	p.Metadata.Name = name
	p.Metadata.Namespace = "ingress-nginx"
	p.Metadata.Labels = map[string]string{
		ingressControllerNameLabel:      ingressControllerName,
		ingressControllerComponentLabel: ingressControllerComponent,
	}
	p.Spec.Containers = []Container{{Name: "controller"}}
	p.Status.Phase = "Running"
	p.Status.PodIP = "10.0.0.5"
	p.Status.StartTime = started.UTC().Format(time.RFC3339)
	return p
}

// probeLine is one JSON access line, with the kubelet's timestamp in front.
func probeLine(at time.Time, ip, path, requestID string) string {
	return at.UTC().Format(time.RFC3339Nano) + " " +
		fmt.Sprintf(`{"time":"%s","ip":"%s","method":"GET","host":"shop.example","path":"%s","protocol":"HTTP/1.1","status":"404","bytes":"512","user_agent":"curl/8.11.1","content_type":"","response_type":"text/html","next_action":"","rsc":"","namespace":"shop","ingress":"web","upstream":"shop-web-3000","request_id":"%s"}`,
			at.UTC().Format(time.RFC3339), ip, path, requestID) + "\n"
}

type fakeLogs struct {
	t       *testing.T
	mu      sync.Mutex
	handler map[string]func(w http.ResponseWriter, r *http.Request, attempt int)
	calls   map[string][]*http.Request
	at      map[string][]time.Time
}

func newFakeLogs(t *testing.T) (*fakeLogs, *Client) {
	f := &fakeLogs{t: t, handler: map[string]func(http.ResponseWriter, *http.Request, int){}, calls: map[string][]*http.Request{}, at: map[string][]time.Time{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/") // /api/v1/namespaces/<ns>/pods/<pod>/log
		if len(parts) != 8 || parts[7] != "log" {
			http.NotFound(w, r)
			return
		}
		pod := parts[6]
		f.mu.Lock()
		f.calls[pod] = append(f.calls[pod], r)
		f.at[pod] = append(f.at[pod], time.Now())
		attempt := len(f.calls[pod])
		h := f.handler[pod]
		f.mu.Unlock()
		if h == nil {
			<-r.Context().Done()
			return
		}
		h(w, r, attempt)
	}))
	t.Cleanup(srv.Close)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f, &Client{cfg: Config{Host: srv.URL, TokenPath: tokenPath}, base: srv.URL, list: srv.Client(), stream: srv.Client()}
}

func (f *fakeLogs) attempts(pod string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls[pod])
}

func stream(lines ...string) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, r *http.Request, _ int) {
		for _, l := range lines {
			_, _ = io.WriteString(w, l)
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestFollowers(client *Client, tr *edgeTracker) *logFollowers {
	f := newLogFollowers(client, "ingress-nginx", tr, func() []string { return clusterHosts }, quietLogger())
	f.retryMin, f.retryMax, f.forbiddenRetry = 20*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond
	return f
}

// requestsSeen drains the tracker until each address in want was counted at
// least that often, then waits a little longer to make sure no more arrive.
func requestsSeen(t *testing.T, tr *edgeTracker, want map[string]int) map[string]int {
	t.Helper()
	got := map[string]int{}
	drain := func() {
		probes, _, _ := tr.Flush(time.Now())
		for _, p := range probes {
			n, _ := strconv.Atoi(p.Labels["requests"])
			got[p.Labels["source_ip"]] += n
		}
	}
	done := func() bool {
		for ip, n := range want {
			if got[ip] < n {
				return false
			}
		}
		return true
	}
	for deadline := time.Now().Add(5 * time.Second); !done() && time.Now().Before(deadline); {
		drain()
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	drain()
	return got
}

func TestFollowsEveryControllerReplica(t *testing.T) {
	logs, client := newFakeLogs(t)
	now := time.Now()
	logs.handler["c1"] = stream(probeLine(now, "203.0.113.1", "/.env", "r1"))
	logs.handler["c2"] = stream(probeLine(now, "203.0.113.2", "/.env", "r2"))
	tr := newEdgeTracker(maxTrackedAddresses)
	f := newTestFollowers(client, tr)
	defer f.Stop()
	f.Reconcile([]Pod{controllerPod("c1", now.Add(-time.Hour)), controllerPod("c2", now.Add(-time.Hour))})

	want := map[string]int{"203.0.113.1": 1, "203.0.113.2": 1}
	if got := requestsSeen(t, tr, want); len(got) != 2 || got["203.0.113.1"] != 1 || got["203.0.113.2"] != 1 {
		t.Errorf("requests %v, want %v", got, want)
	}
	logs.mu.Lock()
	q := logs.calls["c1"][0].URL.Query()
	logs.mu.Unlock()
	if q.Get("follow") != "true" || q.Get("timestamps") != "true" || q.Get("container") != "controller" {
		t.Errorf("query %v", q)
	}
	if st := f.Stats(time.Now()); !st.Reading || st.Replicas != 2 {
		t.Errorf("stats %+v", st)
	}
}

func TestResumesWithoutRepeats(t *testing.T) {
	logs, client := newFakeLogs(t)
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	line := func(i int) string {
		return probeLine(base.Add(time.Duration(i)*time.Second), "203.0.113.7", "/.env."+strconv.Itoa(i), "req-"+strconv.Itoa(i))
	}
	var since string
	logs.handler["c1"] = func(w http.ResponseWriter, r *http.Request, attempt int) {
		if attempt == 1 {
			for i := 1; i <= 3; i++ {
				_, _ = io.WriteString(w, line(i))
			}
			return // the stream ends: a reconnect follows
		}
		logs.mu.Lock()
		since = r.URL.Query().Get("sinceTime")
		logs.mu.Unlock()
		stream(line(2), line(3), line(4))(w, r, attempt)
	}
	tr := newEdgeTracker(maxTrackedAddresses)
	f := newTestFollowers(client, tr)
	defer f.Stop()
	f.Reconcile([]Pod{controllerPod("c1", base.Add(-time.Hour))})

	if got := requestsSeen(t, tr, map[string]int{"203.0.113.7": 4}); got["203.0.113.7"] != 4 {
		t.Errorf("%d requests counted, want 4 (no repeats)", got["203.0.113.7"])
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if want := base.Add(3 * time.Second).UTC().Format(time.RFC3339); since != want {
		t.Errorf("sinceTime %q, want %q", since, want)
	}
}

func TestRolloutReportsTheGap(t *testing.T) {
	logs, client := newFakeLogs(t)
	logs.handler["c2"] = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"kind":"Status","message":"container \"controller\" in pod \"c2\" is waiting to start: ContainerCreating","reason":"BadRequest"}`)
	}
	tr := newEdgeTracker(maxTrackedAddresses)
	f := newTestFollowers(client, tr)
	defer f.Stop()
	var mu sync.Mutex
	clock := time.Now()
	f.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }

	f.Reconcile([]Pod{controllerPod("c1", clock.Add(-time.Hour))})
	f.Reconcile([]Pod{controllerPod("c2", clock)}) // c1 replaced by c2
	for deadline := time.Now().Add(5 * time.Second); logs.attempts("c2") == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	clock = clock.Add(90 * time.Second)
	at := clock
	mu.Unlock()
	st := f.Stats(at)
	if st.GapSeconds < 90 || st.Reading {
		t.Errorf("stats %+v", st)
	}
}

func TestForbiddenMeansNotReading(t *testing.T) {
	logs, client := newFakeLogs(t)
	logs.handler["c1"] = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"kind":"Status","message":"pods \"c1\" is forbidden: User \"system:serviceaccount:netwarden:netwarden-agent\" cannot get resource \"pods/log\"","reason":"Forbidden"}`)
	}
	tr := newEdgeTracker(maxTrackedAddresses)
	f := newTestFollowers(client, tr)
	defer f.Stop()
	f.Reconcile([]Pod{controllerPod("c1", time.Now().Add(-time.Hour))})
	time.Sleep(300 * time.Millisecond)

	st := f.Stats(time.Now())
	if st.Reading || !st.Forbidden {
		t.Errorf("stats %+v", st)
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	at := logs.at["c1"]
	if len(at) < 2 {
		t.Fatalf("%d attempts: a 403 is retried", len(at))
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < f.forbiddenRetry/2 {
			t.Errorf("retry %d after %v: no backoff", i, gap)
		}
	}
}

func TestNoControllerMeansNotReading(t *testing.T) {
	_, client := newFakeLogs(t)
	f := newTestFollowers(client, newEdgeTracker(maxTrackedAddresses))
	defer f.Stop()
	other := controllerPod("web-1", time.Now())
	other.Metadata.Labels = map[string]string{"app": "web"}
	f.Reconcile([]Pod{other})
	if st := f.Stats(time.Now()); st.Reading || st.Replicas != 0 {
		t.Errorf("stats %+v", st)
	}
}

// edgeAPIServer is a cluster with one ingress-nginx controller whose log
// carries the given lines; every other list is empty and every watch idles.
func edgeAPIServer(t *testing.T, lines ...string) Config {
	t.Helper()
	pod := `{"metadata":{"name":"ingress-nginx-controller-7d9","namespace":"ingress-nginx","labels":{"app.kubernetes.io/name":"ingress-nginx","app.kubernetes.io/component":"controller"}},` +
		`"spec":{"containers":[{"name":"controller","image":"registry.k8s.io/ingress-nginx/controller:v1.15.1"}]},` +
		`"status":{"phase":"Running","podIP":"10.0.0.5","startTime":"2026-10-01T00:00:00Z"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/log"):
			for _, l := range lines {
				_, _ = io.WriteString(w, l)
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case r.URL.Path == "/version":
			_, _ = io.WriteString(w, `{"gitVersion":"v1.33.0"}`)
		case r.URL.Query().Get("watch") == "1":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case r.URL.Path == "/api/v1/pods":
			_, _ = io.WriteString(w, `{"metadata":{"resourceVersion":"1"},"items":[`+pod+`]}`)
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

func gauges(ms []metrics.Metric) map[string]float64 {
	out := map[string]float64{}
	for _, m := range ms {
		if len(m.Labels) == 1 {
			out[m.Name] = m.Value
		}
	}
	return out
}

func TestCollectWritesEdgeEventsAndMetrics(t *testing.T) {
	old := initialSyncTimeout
	initialSyncTimeout = 2 * time.Second
	t.Cleanup(func() { initialSyncTimeout = old })

	now := time.Now()
	exposure := strings.Replace(strings.Replace(probeLine(now, "203.0.113.30", "/.env", "x1"), `"status":"404"`, `"status":"200"`, 1),
		`"response_type":"text/html"`, `"response_type":"text/plain"`, 1)
	cfg := edgeAPIServer(t,
		probeLine(now, "203.0.113.30", "/.git/config", "p1"),
		probeLine(now, "203.0.113.30", "/wp-login.php", "p2"),
		exposure,
		now.UTC().Format(time.RFC3339Nano)+" 2026/10/24 12:57:01 [warn] 165#165: *1 a client request body is buffered\n",
		now.UTC().Format(time.RFC3339Nano)+" not an access line\n",
	)
	spoolDir := filepath.Join(t.TempDir(), "spool")
	urgent := make(chan struct{}, 4)
	c := NewCollector("prod-cluster", WithConfig(cfg), WithLogger(quietLogger()),
		WithCapabilities(Capabilities{IngressLogs: true}), WithIngressLogs("ingress-nginx"),
		WithSpoolDir(spoolDir), WithUrgent(func() { urgent <- struct{}{} }))
	t.Cleanup(func() { _ = c.Close() })

	if _, err := c.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-urgent:
	case <-time.After(5 * time.Second):
		t.Fatal("the exposure did not ask for an early report")
	}
	ms, err := c.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := gauges(ms)
	want := map[string]float64{
		"k8s_ingress_log_reading": 1, "k8s_ingress_log_full_format": 1, "k8s_ingress_log_unparsed": 1,
		"k8s_ingress_log_sources_flagged": 1, "k8s_ingress_log_sources_dropped": 0,
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %v, want %v", name, got[name], v)
		}
	}
	if got["k8s_ingress_log_lines"] < 3 {
		t.Errorf("lines %v", got["k8s_ingress_log_lines"])
	}
	blind := false
	for _, m := range ms {
		if m.Name == "k8s_ingress_log_server_action_blind" && m.Labels["ingress"] == "shop/web" && m.Labels["reason"] == "learning" && m.Value == 1 {
			blind = true
		}
	}
	if !blind {
		t.Error("no server-action blind series for a newly seen ingress")
	}

	files, _ := filepath.Glob(filepath.Join(spoolDir, "events", "edge-*.jsonl"))
	var types []string
	for _, f := range files {
		data, _ := os.ReadFile(f)
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			e, err := spool.ParseEvent([]byte(line))
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			types = append(types, e.Type)
		}
	}
	sort.Strings(types)
	if strings.Join(types, ",") != "web.exposure,web.probe" {
		t.Errorf("spooled %v", types)
	}
	if _, err := os.Stat(filepath.Join(spoolDir, "edge", "state.json")); err != nil {
		t.Errorf("learning not saved: %v", err)
	}
}

func TestIngressLogsWithoutSpoolReportsNotReading(t *testing.T) {
	old := initialSyncTimeout
	initialSyncTimeout = 2 * time.Second
	t.Cleanup(func() { initialSyncTimeout = old })

	c := NewCollector("prod-cluster", WithConfig(edgeAPIServer(t)), WithLogger(quietLogger()),
		WithCapabilities(Capabilities{IngressLogs: true}), WithIngressLogs("ingress-nginx"))
	t.Cleanup(func() { _ = c.Close() })
	ms, err := c.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := gauges(ms); got["k8s_ingress_log_reading"] != 0 {
		t.Errorf("reading = %v with nowhere to write events", got["k8s_ingress_log_reading"])
	}
}

func TestIngressLogsOffEmitsNothing(t *testing.T) {
	old := initialSyncTimeout
	initialSyncTimeout = 2 * time.Second
	t.Cleanup(func() { initialSyncTimeout = old })

	c := NewCollector("prod-cluster", WithConfig(edgeAPIServer(t)), WithLogger(quietLogger()),
		WithCapabilities(Capabilities{}), WithSpoolDir(t.TempDir()))
	t.Cleanup(func() { _ = c.Close() })
	ms, err := c.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if strings.HasPrefix(m.Name, "k8s_ingress_log_") {
			t.Errorf("%s emitted with the capability off", m.Name)
		}
	}
}

// The Host header is whatever the client sends. A scanner that reaches the
// load balancer by IP, or names someone else's site, has not probed one of
// yours: only the cluster's own Ingress host names count as sites.
func TestOnlyOwnHostsAreSites(t *testing.T) {
	logs, client := newFakeLogs(t)
	now := time.Now()
	line := func(host, path, id string) string {
		return strings.Replace(probeLine(now, "203.0.113.60", path, id), `"host":"shop.example"`, `"host":"`+host+`"`, 1)
	}
	logs.handler["c1"] = stream(
		line("moriah.app", "/.env", "h1"),
		line("143.198.11.97", "/.git/config", "h2"),
		line("victim.example", "/.env.local", "h3"),
		line("shop.wild.example", "/.aws/credentials", "h4"),
	)
	tr := newEdgeTracker(maxTrackedAddresses)
	f := newLogFollowers(client, "ingress-nginx", tr, func() []string { return []string{"moriah.app", "*.wild.example"} }, quietLogger())
	defer f.Stop()
	f.Reconcile([]Pod{controllerPod("c1", now.Add(-time.Hour))})

	var probe map[string]string
	for deadline := time.Now().Add(5 * time.Second); probe == nil && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if tr.tracked() == 1 {
			time.Sleep(100 * time.Millisecond)
			probes, _, _ := tr.Flush(time.Now())
			if len(probes) == 1 {
				probe = probes[0].Labels
			}
		}
	}
	if probe == nil {
		t.Fatal("no probe")
	}
	if probe["hosts"] != "moriah.app,shop.wild.example" || probe["hosts_count"] != "2" || probe["requests"] != "4" {
		t.Errorf("hosts %q count %q requests %q", probe["hosts"], probe["hosts_count"], probe["requests"])
	}
}

func TestOwnHost(t *testing.T) {
	hosts := []string{"moriah.app", "*.wild.example"}
	for host, want := range map[string]bool{
		"moriah.app": true, "MORIAH.APP": true, "moriah.app:443": true, "a.wild.example": true,
		"wild.example": false, "a.b.wild.example": false, "evil-moriah.app": false, "143.198.11.97": false, "": false,
	} {
		if got := ownHost(host, hosts); got != want {
			t.Errorf("ownHost(%q) = %v, want %v", host, got, want)
		}
	}
}
