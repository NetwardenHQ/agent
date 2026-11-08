package k8s

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/spool"
)

var edgeT0 = time.Date(2026, 10, 23, 14, 0, 0, 0, time.UTC)

func access(ip, host, method, path string, status int, size int64) AccessLine {
	return AccessLine{
		Time: edgeT0, IP: ip, Method: method, Host: host, Path: path, Protocol: "HTTP/1.1", Status: status, Bytes: size,
		UserAgent: "Mozilla/5.0", ResponseType: "text/html", Namespace: "shop", Ingress: "web",
		Upstream: "shop-web-3000", RequestID: fmt.Sprintf("%s-%s-%d", ip, path, status), Full: true,
	}
}

func observe(tr *edgeTracker, l AccessLine) {
	blind, _ := tr.ServerActionBlind(l, l.Time)
	tr.Observe(l, Classify(l, clusterHosts, blind))
}

func newTestTracker() *edgeTracker {
	tr := newEdgeTracker(maxTrackedAddresses)
	tr.now = func() time.Time { return edgeT0 }
	return tr
}

func allText(events []spool.Event) string {
	var b strings.Builder
	for _, e := range events {
		b.WriteString(e.Title)
		b.WriteString(e.DedupeKey)
		for k, v := range e.Labels {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	return b.String()
}

func TestOnlyFlaggedAddressesLeave(t *testing.T) {
	tr := newTestTracker()
	for i := 0; i < 1000; i++ {
		observe(tr, access(fmt.Sprintf("198.51.100.%d", i%250+1), "shop.example", "GET", fmt.Sprintf("/products/%d", i), 200, 4096))
	}
	for _, p := range []string{"/.env", "/.git/config", "/wp-login.php"} {
		observe(tr, access("203.0.113.9", "shop.example", "GET", p, 404, 512))
	}
	probes, exposures, stats := tr.Flush(edgeT0.Add(time.Minute))
	if len(probes) != 1 || len(exposures) != 0 {
		t.Fatalf("probes %d exposures %d", len(probes), len(exposures))
	}
	if probes[0].Labels["source_ip"] != "203.0.113.9" {
		t.Errorf("source %q", probes[0].Labels["source_ip"])
	}
	if strings.Contains(allText(probes), "198.51.100.") || strings.Contains(allText(probes), "/products/") {
		t.Error("normal traffic left the agent")
	}
	if stats.Lines != 1003 || stats.Flagged != 1 {
		t.Errorf("stats %+v", stats)
	}
	// The window starts over.
	if probes, _, _ := tr.Flush(edgeT0.Add(2 * time.Minute)); len(probes) != 0 {
		t.Errorf("a flushed source was reported again")
	}
}

func TestProbeEventLabels(t *testing.T) {
	tr := newTestTracker()
	tr.windowStart = edgeT0
	l := access("203.0.113.9", "moriah.app", "GET", "/.env", 404, 512)
	l.UserAgent = "CCBot/2.0 (https://commoncrawl.org/faq/)"
	observe(tr, l)
	for i := 0; i < 30; i++ {
		l := access("203.0.113.9", fmt.Sprintf("site-%d.example", i%3), "GET", fmt.Sprintf("/backup-%02d-%s.sql", i, strings.Repeat("x", 20)), 404, 512)
		l.UserAgent = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"
		observe(tr, l)
	}
	observe(tr, access("203.0.113.9", "moriah.app", "GET", "/.env", 200, 5120))
	probes, _, _ := tr.Flush(edgeT0.Add(10 * time.Minute))
	if len(probes) != 1 {
		t.Fatalf("%d probes", len(probes))
	}
	e := probes[0]
	if e.V != 1 || e.Type != "web.probe" || e.Severity != "info" {
		t.Errorf("event %+v", e)
	}
	want := map[string]string{
		"source_ip": "203.0.113.9", "requests": "32", "not_found": "31", "hosts_count": "4",
		"classes": "secret_file,crawler_claim", "paths_total": "31", "statuses": "404:31,200:1",
		"crawler_claims": "CCBot,GPTBot", "ua_count": "3", "ua_sample": "CCBot/2.0 (https://commoncrawl.org/faq/)",
		"format": "json", "signature_version": SignatureVersion, "window_start": strconv.FormatInt(edgeT0.Unix(), 10),
	}
	for k, v := range want {
		if e.Labels[k] != v {
			t.Errorf("%s = %q, want %q", k, e.Labels[k], v)
		}
	}
	for k, v := range e.Labels {
		if len(v) > labelMax {
			t.Errorf("%s is %d characters", k, len(v))
		}
	}
	if !strings.HasPrefix(e.Labels["paths"], "/.env,/backup-00-") || strings.Count(e.Labels["paths"], ",") >= 30 {
		t.Errorf("paths %q", e.Labels["paths"])
	}
	if !strings.HasPrefix(e.Labels["hosts"], "moriah.app,") {
		t.Errorf("hosts %q", e.Labels["hosts"])
	}
	if e.DedupeKey != "probe:203.0.113.9:"+strconv.FormatInt(edgeT0.Unix(), 10) {
		t.Errorf("dedupe key %q", e.DedupeKey)
	}
	if e.Title != "203.0.113.9 probed 4 sites (secret files, crawler names)" {
		t.Errorf("title %q", e.Title)
	}
	if err := spool.WriteEvents(t.TempDir(), "edge-test", probes); err != nil {
		t.Errorf("not a valid spool event: %v", err)
	}
}

func learnShape(tr *edgeTracker, full bool, size int64) {
	for i := 0; i < 5; i++ {
		l := access("198.51.100.20", "shop.example", "GET", fmt.Sprintf("/missing-%d", i), 404, size)
		l.Full = full
		if !full {
			l.ResponseType, l.Namespace, l.Ingress, l.Host = "", "", "", ""
		}
		observe(tr, l)
	}
}

func TestExposureLikelyAndPossible(t *testing.T) {
	tr := newTestTracker()
	learnShape(tr, true, 5120)
	l := access("203.0.113.9", "shop.example", "GET", "/.env", 200, 1229)
	l.ResponseType = "text/plain"
	observe(tr, l)
	_, exposures, _ := tr.Flush(edgeT0.Add(time.Minute))
	if len(exposures) != 1 {
		t.Fatalf("%d exposures", len(exposures))
	}
	e := exposures[0]
	for k, v := range map[string]string{
		"source_ip": "203.0.113.9", "host": "shop.example", "path": "/.env", "status": "200", "response_type": "text/plain",
		"bytes": "1229", "not_found_type": "text/html", "not_found_bytes": "5120", "verdict": "likely", "format": "json",
	} {
		if e.Labels[k] != v {
			t.Errorf("%s = %q, want %q", k, e.Labels[k], v)
		}
	}
	if e.Type != "web.exposure" || e.DedupeKey != "exposure:"+l.RequestID {
		t.Errorf("event %+v", e)
	}
	if e.Title != "shop.example sent /.env (text/plain, 1229 bytes) to 203.0.113.9" {
		t.Errorf("title %q", e.Title)
	}

	// The default format has no response type: only the size can tell.
	tr = newTestTracker()
	learnShape(tr, false, 548)
	unlike := access("203.0.113.9", "", "GET", "/.env", 200, 1229)
	unlike.Full, unlike.ResponseType, unlike.Namespace, unlike.Ingress = false, "", "", ""
	observe(tr, unlike)
	near := unlike
	near.Path, near.Bytes, near.RequestID = "/.git/config", 560, "near"
	observe(tr, near)
	_, exposures, _ = tr.Flush(edgeT0.Add(time.Minute))
	if len(exposures) != 1 || exposures[0].Labels["verdict"] != "possible" || exposures[0].Labels["path"] != "/.env" {
		t.Fatalf("exposures %+v", exposures)
	}
	if exposures[0].Labels["response_type"] != "" || exposures[0].Labels["format"] != "default" || exposures[0].Labels["not_found_bytes"] != "548" {
		t.Errorf("labels %+v", exposures[0].Labels)
	}
	if !strings.Contains(exposures[0].Title, "(unknown type, 1229 bytes)") {
		t.Errorf("title %q", exposures[0].Title)
	}
}

func TestCatchAllAppIsNotAnExposure(t *testing.T) {
	for _, full := range []bool{true, false} {
		tr := newTestTracker()
		// A single-page app answers every path with its index page.
		for i, p := range []string{"/", "/about", "/.env", "/.git/config", "/.env.local", "/values.yaml", "/.aws/credentials", "/backup.sql"} {
			l := access("203.0.113.9", "spa.example", "GET", p, 200, 2048)
			l.RequestID = strconv.Itoa(i)
			l.Full = full
			if !full {
				l.ResponseType, l.Namespace, l.Ingress, l.Host = "", "", "", ""
			}
			observe(tr, l)
		}
		if _, exposures, _ := tr.Flush(edgeT0.Add(time.Minute)); len(exposures) != 0 {
			t.Errorf("full=%v: %d exposures from a catch-all page", full, len(exposures))
		}
	}
}

func TestExposureCallsUrgentOncePer30s(t *testing.T) {
	tr := newTestTracker()
	calls := 0
	tr.urgent = func() { calls++ }
	clock := edgeT0
	tr.now = func() time.Time { return clock }
	for i, offset := range []time.Duration{0, 10 * time.Second, 31 * time.Second} {
		clock = edgeT0.Add(offset)
		l := access("203.0.113.9", "shop.example", "GET", "/.env", 200, 1229)
		l.ResponseType, l.RequestID = "application/octet-stream", strconv.Itoa(i)
		observe(tr, l)
	}
	if calls != 2 {
		t.Errorf("urgent called %d times", calls)
	}
}

func TestEvictsUnflaggedFirst(t *testing.T) {
	tr := newEdgeTracker(20000)
	tr.now = func() time.Time { return edgeT0 }
	observe(tr, access("203.0.113.9", "shop.example", "GET", "/.env", 404, 512))
	for i := 0; i < 20000; i++ {
		observe(tr, access(addrN(i), "shop.example", "GET", "/", 200, 4096))
	}
	if tr.tracked() != 20000 {
		t.Fatalf("tracking %d addresses", tr.tracked())
	}
	probes, _, _ := tr.Flush(edgeT0.Add(time.Minute))
	if len(probes) != 1 || probes[0].Labels["source_ip"] != "203.0.113.9" {
		t.Fatalf("the flagged address was evicted: %d probes", len(probes))
	}
}

// addrN is a distinct public address per n.
func addrN(n int) string { return fmt.Sprintf("2001:db8:%x::%x", n/65536, n%65536) }

func TestCapsProbeEventsPerCycle(t *testing.T) {
	tr := newTestTracker()
	for i := 0; i < 150; i++ {
		for j := 0; j <= i%7; j++ {
			observe(tr, access(addrN(i), "shop.example", "GET", fmt.Sprintf("/.env.%d", j), 404, 512))
		}
	}
	probes, _, stats := tr.Flush(edgeT0.Add(time.Minute))
	if len(probes) != maxProbeEventsPerCycle || stats.Dropped != 50 || stats.Flagged != 150 {
		t.Fatalf("probes %d stats %+v", len(probes), stats)
	}
	last, _ := strconv.Atoi(probes[len(probes)-1].Labels["requests"])
	for _, p := range probes {
		if n, _ := strconv.Atoi(p.Labels["requests"]); n < last {
			t.Fatalf("not ordered by requests")
		}
	}
	if first, _ := strconv.Atoi(probes[0].Labels["requests"]); first != 7 {
		t.Errorf("busiest first: %d", first)
	}
}

func TestCostAtTenTimesToday(t *testing.T) {
	if testing.Short() {
		t.Skip("measures cost")
	}
	lines := make([]AccessLine, 4096)
	for i := range lines {
		lines[i] = access(addrN(i), "shop.example", "GET", fmt.Sprintf("/products/%d", i), 200, 4096)
		if i%97 == 0 {
			lines[i].Path = "/.env"
		}
	}
	res := testing.Benchmark(func(b *testing.B) {
		tr := newEdgeTracker(maxTrackedAddresses)
		for i := 0; b.Loop(); i++ {
			l := lines[i%len(lines)]
			tr.Observe(l, Classify(l, clusterHosts, false))
		}
	})
	t.Logf("%d ns and %d allocations per line", res.NsPerOp(), res.AllocsPerOp())
	if per := res.NsPerOp(); per > 20_000 {
		t.Errorf("%d ns per line", per)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	tr := newEdgeTracker(maxTrackedAddresses)
	for i := 0; i < maxTrackedAddresses; i++ {
		for _, p := range []string{"/", "/products/1", "/cart"} {
			l := access(addrN(i), "shop.example", "GET", p, 200, 4096)
			tr.Observe(l, nil)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d tracked addresses: %.1f MiB", maxTrackedAddresses, float64(grown)/(1<<20))
	if grown > 40<<20 {
		t.Errorf("%d addresses use %d MiB", maxTrackedAddresses, grown>>20)
	}
	runtime.KeepAlive(tr)
}

func serverAction(ip string, at time.Time) AccessLine {
	l := access(ip, "shop.example", "POST", "/checkout", 200, 300)
	l.NextAction, l.RSC, l.ContentType, l.Time = "7f3a", "1", "text/x-component", at
	return l
}

func TestServerActionBlindPerIngress(t *testing.T) {
	tr := newTestTracker()
	first := access("198.51.100.1", "shop.example", "GET", "/", 200, 100)
	observe(tr, first)
	if blind, reason := tr.ServerActionBlind(first, edgeT0); !blind || reason != "learning" {
		t.Errorf("new ingress: blind=%v reason=%q", blind, reason)
	}
	// A probe while learning is not called a server action.
	probe := serverAction("203.0.113.9", edgeT0.Add(time.Hour))
	probe.Status = 404
	if classes := Classify(probe, nil, true); len(classes) != 0 {
		t.Errorf("classes %v", classes)
	}

	for i := 0; i < serverActionLearnAddresses; i++ {
		observe(tr, serverAction(fmt.Sprintf("198.51.100.%d", 10+i), edgeT0.Add(time.Duration(i)*time.Hour)))
	}
	if blind, reason := tr.ServerActionBlind(first, edgeT0.Add(24*time.Hour)); !blind || reason != "serves_actions" {
		t.Errorf("serving ingress: blind=%v reason=%q", blind, reason)
	}

	quiet := access("198.51.100.1", "blog.example", "GET", "/", 200, 100)
	quiet.Ingress = "blog"
	observe(tr, quiet)
	if blind, _ := tr.ServerActionBlind(quiet, edgeT0.Add(6*24*time.Hour)); !blind {
		t.Error("blind for the first seven days")
	}
	if blind, reason := tr.ServerActionBlind(quiet, edgeT0.Add(7*24*time.Hour+time.Hour)); blind {
		t.Errorf("still blind after seven quiet days: %q", reason)
	}
	reasons := func(at time.Time) map[string]string {
		got := map[string]string{}
		for _, b := range tr.BlindIngresses(at) {
			got[b.Ingress] = b.Reason
		}
		return got
	}
	if got := reasons(edgeT0.Add(24 * time.Hour)); got["shop/web"] != "serves_actions" || got["shop/blog"] != "learning" {
		t.Errorf("blind ingresses on day one: %v", got)
	}
	if got := reasons(edgeT0.Add(7*24*time.Hour + time.Hour)); got["shop/blog"] != "" {
		t.Errorf("blind ingresses after a week: %v", got)
	}
}

func TestLearningSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	tr := newTestTracker()
	learnShape(tr, true, 5120)
	for i := 0; i < serverActionLearnAddresses; i++ {
		observe(tr, serverAction(fmt.Sprintf("203.0.113.%d", 50+i), edgeT0))
	}
	if err := tr.Save(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "edge", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("203.0.113.")) || bytes.Contains(raw, []byte("198.51.100.")) {
		t.Error("client addresses written to disk")
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	again := loadEdgeTracker(dir, maxTrackedAddresses, logger)
	l := access("198.51.100.1", "shop.example", "GET", "/", 200, 100)
	if blind, reason := again.ServerActionBlind(l, edgeT0.Add(time.Hour)); !blind || reason != "serves_actions" {
		t.Errorf("after restart: blind=%v reason=%q", blind, reason)
	}
	exposed := access("203.0.113.9", "shop.example", "GET", "/.env", 200, 900)
	exposed.ResponseType = "text/html" // judged by size against the remembered shape
	again.now = func() time.Time { return edgeT0 }
	observe(again, exposed)
	if _, exposures, _ := again.Flush(edgeT0.Add(time.Minute)); len(exposures) != 1 {
		t.Errorf("the not-found shape was not remembered: %d exposures", len(exposures))
	}

	if err := os.WriteFile(filepath.Join(dir, "edge", "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	fresh := loadEdgeTracker(dir, maxTrackedAddresses, logger)
	if blind, reason := fresh.ServerActionBlind(l, edgeT0.Add(time.Hour)); !blind || reason != "learning" {
		t.Errorf("a corrupt file must start learning over: %v %q", blind, reason)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Errorf("%d warnings for a corrupt state file:\n%s", n, logs.String())
	}
}
