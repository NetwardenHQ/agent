package k8s

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ingressMetricsDisabled is what ingress-nginx v1.15.1 serves on :10254 when
// its collectors are not registered: HTTP 200, valid Prometheus text, and
// nothing but Go runtime series.
const ingressMetricsDisabled = `
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 92
go_gc_duration_seconds{quantile="0"} 6.7788e-05
process_open_fds 45
promhttp_metric_handler_requests_total{code="200"} 3
`

// ingressBody is the same endpoint with metrics enabled, carrying the full
// label set ingress-nginx emits.
func ingressBody(requests, bytesIn, bytesOut, durSum, durCnt, errors string) string {
	return `
nginx_ingress_controller_build_info{controller_class="k8s.io/ingress-nginx",release="v1.15.1"} 1
nginx_ingress_controller_config_last_reload_successful{controller_pod="c1"} 1
nginx_ingress_controller_nginx_process_connections{controller_pod="c1",state="active"} 12
nginx_ingress_controller_nginx_process_connections{controller_pod="c1",state="waiting"} 7
nginx_ingress_controller_nginx_process_connections{controller_pod="c1",state="reading"} 1
nginx_ingress_controller_requests{controller_pod="c1",host="a.example.com",ingress="web",method="GET",namespace="shop",path="/",service="web",status="200"} ` + requests + `
nginx_ingress_controller_requests{controller_pod="c1",host="a.example.com",ingress="web",method="GET",namespace="shop",path="/",service="web",status="503"} ` + errors + `
nginx_ingress_controller_requests{controller_pod="c1",host="a.example.com",ingress="web",method="GET",namespace="shop",path="/x",service="web",status="404"} 50
nginx_ingress_controller_request_size_sum{controller_pod="c1",host="a.example.com",ingress="web",method="GET",namespace="shop",path="/",service="web",status="200"} ` + bytesIn + `
nginx_ingress_controller_response_size_sum{controller_pod="c1",host="a.example.com",ingress="web",method="GET",namespace="shop",path="/",service="web",status="200"} ` + bytesOut + `
nginx_ingress_controller_request_duration_seconds_sum{controller_pod="c1",host="a.example.com",ingress="web",method="GET",namespace="shop",path="/",service="web",status="200"} ` + durSum + `
nginx_ingress_controller_request_duration_seconds_count{controller_pod="c1",host="a.example.com",ingress="web",method="GET",namespace="shop",path="/",service="web",status="200"} ` + durCnt + `
nginx_ingress_controller_request_duration_seconds_bucket{le="0.1",ingress="web",namespace="shop"} 900
`
}

func ingressSamples(body string) []promSample {
	return parseProm(body, ingressWanted)
}

func TestMetricsDisabledIsNotZeroTraffic(t *testing.T) {
	got := ingressSamples(ingressMetricsDisabled)
	if len(got) != 0 {
		t.Fatalf("lifted %d series off a metrics-disabled controller: %+v", len(got), got)
	}

	c := NewCollector("prod-cluster")
	if out := c.emitIngress(ingressReport{MetricsEnabled: false, Routes: []ingressRouteState{
		{Namespace: "shop", Name: "web"},
	}}, time.Now()); len(out) != 0 {
		t.Fatalf("emitted %d series with the controller's metrics disabled", len(out))
	}
}

func TestHistogramBucketsAreNotLifted(t *testing.T) {
	for _, s := range ingressSamples(ingressBody("1000", "1", "1", "1", "1", "1")) {
		if strings.HasSuffix(s.Name, "_bucket") {
			t.Fatalf("lifted a histogram bucket: %s", s.Name)
		}
	}
}

func TestOnlyServerErrorsCountAsErrors(t *testing.T) {
	c := NewCollector("prod-cluster")
	pods := []Pod{ingressControllerPod("c1", "10.0.0.1")}
	c.ingresses = testReflector(Ingress{
		Metadata: ObjectMeta{Namespace: "shop", Name: "web"},
	})

	now := time.Unix(1_789_000_000, 0)
	feed(t, c, pods, ingressBody("1000", "0", "0", "0", "0", "10"), now)
	r := feed(t, c, pods, ingressBody("1100", "0", "0", "0", "0", "20"), now.Add(10*time.Second))

	route := r.Routes[0]
	if route.RequestsPerSecond == nil || *route.RequestsPerSecond != 11 {
		// 100 more 200s + 10 more 503s over 10s. The 404 series is flat.
		t.Fatalf("requests/s = %v, want 11", route.RequestsPerSecond)
	}
	if route.ErrorsPerSecond == nil || *route.ErrorsPerSecond != 1 {
		t.Fatalf("errors/s = %v, want 1 (503 only, not the 404)", route.ErrorsPerSecond)
	}
}

func TestBandwidthAndLatencyFromCounterDeltas(t *testing.T) {
	c := NewCollector("prod-cluster")
	pods := []Pod{ingressControllerPod("c1", "10.0.0.1")}
	c.ingresses = testReflector(Ingress{
		Metadata: ObjectMeta{Namespace: "shop", Name: "web"},
		Spec: IngressSpec{
			IngressClassName: "nginx",
			Rules:            []IngressRule{{Host: "a.example.com"}},
			TLS:              []IngressTLS{{Hosts: []string{"a.example.com"}}},
		},
	})

	now := time.Unix(1_789_000_000, 0)
	first := feed(t, c, pods, ingressBody("1000", "10000", "500000", "10", "1000", "0"), now)

	// The first scrape has no baseline: inventory, but no rates.
	if first.Routes[0].BytesInPerSecond != nil {
		t.Fatal("invented a bandwidth reading on the first scrape")
	}
	if first.Routes[0].Class != "nginx" || !first.Routes[0].TLS ||
		len(first.Routes[0].Hosts) != 1 || first.Routes[0].Hosts[0] != "a.example.com" {
		t.Fatalf("inventory not carried through: %+v", first.Routes[0])
	}

	// 10s later: +2000 bytes in, +1,000,000 out, +20s over +200 requests.
	r := feed(t, c, pods, ingressBody("1200", "12000", "1500000", "30", "1200", "0"), now.Add(10*time.Second))
	route := r.Routes[0]
	if route.BytesInPerSecond == nil || *route.BytesInPerSecond != 200 {
		t.Fatalf("bytes in/s = %v, want 200", route.BytesInPerSecond)
	}
	if route.BytesOutPerSecond == nil || *route.BytesOutPerSecond != 100000 {
		t.Fatalf("bytes out/s = %v, want 100000", route.BytesOutPerSecond)
	}
	// 20 seconds spread over 200 requests = 100ms each.
	if route.AvgDurationMs == nil || *route.AvgDurationMs != 100 {
		t.Fatalf("avg duration = %v ms, want 100", route.AvgDurationMs)
	}
	if r.BytesOutPerSecond == nil || *r.BytesOutPerSecond != 100000 {
		t.Fatalf("cluster rollup = %v", r.BytesOutPerSecond)
	}
	if !r.MetricsEnabled {
		t.Fatal("metrics_enabled false despite nginx series")
	}
}

func TestOneReplicaRestartingDoesNotDiscardTheOthers(t *testing.T) {
	c := NewCollector("prod-cluster")
	pods := []Pod{
		ingressControllerPod("c1", "10.0.0.1"),
		ingressControllerPod("c2", "10.0.0.2"),
	}
	c.ingresses = testReflector(Ingress{Metadata: ObjectMeta{Namespace: "shop", Name: "web"}})

	now := time.Unix(1_789_000_000, 0)
	bodies := map[string]string{
		"10.0.0.1": ingressBody("1000", "0", "10000", "0", "0", "0"),
		"10.0.0.2": ingressBody("1000", "0", "10000", "0", "0", "0"),
	}
	c.scraper = fakeScraper(bodies)
	c.collectIngress(t.Context(), pods, now)

	// c1 advances normally; c2 restarted and its counters are back near zero.
	c.scraper = fakeScraper(map[string]string{
		"10.0.0.1": ingressBody("1100", "0", "20000", "0", "0", "0"),
		"10.0.0.2": ingressBody("5", "0", "50", "0", "0", "0"),
	})
	r := c.collectIngress(t.Context(), pods, now.Add(10*time.Second))

	// c1 moved 10000 bytes in 10s; c2's negative delta is dropped.
	if r.Routes[0].BytesOutPerSecond == nil || *r.Routes[0].BytesOutPerSecond != 1000 {
		t.Fatalf("bytes out/s = %v, want 1000 from the healthy replica alone",
			r.Routes[0].BytesOutPerSecond)
	}
}

func TestIdleRouteIsListedWithoutInventingTraffic(t *testing.T) {
	// The exporter has never reported "never-used"; it is listed without rates.
	c := NewCollector("prod-cluster")
	pods := []Pod{ingressControllerPod("c1", "10.0.0.1")}
	c.ingresses = testReflector(
		Ingress{Metadata: ObjectMeta{Namespace: "shop", Name: "web"}},
		Ingress{Metadata: ObjectMeta{Namespace: "quiet", Name: "never-used"}},
	)
	now := time.Unix(1_789_000_000, 0)
	feed(t, c, pods, ingressBody("1000", "1", "1", "1", "1", "0"), now)
	r := feed(t, c, pods, ingressBody("1100", "2", "2", "2", "2", "0"), now.Add(10*time.Second))

	var idle *ingressRouteState
	for i := range r.Routes {
		if r.Routes[i].Name == "never-used" {
			idle = &r.Routes[i]
		}
	}
	if idle == nil {
		t.Fatal("an ingress with no traffic disappeared from the report")
	}
	if idle.RequestsPerSecond != nil || idle.BytesInPerSecond != nil {
		t.Fatalf("invented traffic for an idle route: %+v", idle)
	}
}

func TestTopIngressesRanksByBytesAndDropsUnmeasured(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	routes := []ingressRouteState{
		{Namespace: "a", Name: "small", BytesOutPerSecond: f(10)},
		{Namespace: "a", Name: "big", BytesOutPerSecond: f(1000)},
		{Namespace: "a", Name: "idle"}, // never measured
		{Namespace: "a", Name: "mid", BytesInPerSecond: f(100)},
	}
	got := topIngresses(routes, 2)
	if len(got) != 2 || got[0].Name != "big" || got[1].Name != "mid" {
		t.Fatalf("ranking wrong: %+v", got)
	}
	for _, r := range topIngresses(routes, 10) {
		if r.Name == "idle" {
			t.Fatal("an unmeasured route was given a time series")
		}
	}
}

func TestFailedConfigReloadGetsItsOwnSeries(t *testing.T) {
	c := NewCollector("prod-cluster")
	out := c.emitIngress(ingressReport{
		MetricsEnabled: true,
		Controllers: []ingressControllerState{
			{Pod: "c1", Reachable: true, ConfigReloadOK: boolPtr(true)},
			{Pod: "c2", Reachable: true, ConfigReloadOK: boolPtr(false)},
			// Reachable but metrics off: unknown, not a failure.
			{Pod: "c3", Reachable: true},
		},
	}, time.Now())

	var found bool
	for _, m := range out {
		if m.Name == "k8s_ingress_config_reload_failures" {
			found = true
			if m.Value != 1 {
				t.Fatalf("reload failures = %v, want 1", m.Value)
			}
		}
	}
	if !found {
		t.Fatal("no k8s_ingress_config_reload_failures series")
	}
}

func ingressControllerPod(name, ip string) Pod {
	return Pod{
		Metadata: ObjectMeta{
			Namespace: "ingress-nginx",
			Name:      name,
			Labels: map[string]string{
				ingressControllerNameLabel:      ingressControllerName,
				ingressControllerComponentLabel: ingressControllerComponent,
				ingressControllerVersionLabel:   "1.15.1",
			},
		},
		Status: PodStatus{PodIP: ip, Phase: "Running"},
	}
}

func testReflector(items ...Ingress) *reflector[Ingress] {
	r := &reflector[Ingress]{store: newStore[Ingress]()}
	for _, i := range items {
		r.store.put(i.key(), i)
	}
	return r
}

// fakeScraper drives the real scrapeExporter path (URL building, status
// handling and parsing) with canned bodies keyed by pod IP.
func fakeScraper(bodies map[string]string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, ok := bodies[req.URL.Hostname()]
		if !ok {
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// feed runs one collection cycle with the same body served by every controller.
func feed(t *testing.T, c *Collector, pods []Pod, body string, now time.Time) ingressReport {
	t.Helper()
	bodies := map[string]string{}
	for _, p := range pods {
		bodies[p.Status.PodIP] = body
	}
	c.scraper = fakeScraper(bodies)
	return c.collectIngress(t.Context(), pods, now)
}

func TestOrphanedRouteIsDistinguishedFromIdle(t *testing.T) {
	c := NewCollector("prod-cluster")
	pods := []Pod{ingressControllerPod("c1", "10.0.0.1")}
	c.ingresses = testReflector(
		Ingress{Metadata: ObjectMeta{Namespace: "shop", Name: "broken"}},
		Ingress{Metadata: ObjectMeta{Namespace: "shop", Name: "quiet"}},
	)
	body := `
nginx_ingress_controller_build_info{release="v1.15.1"} 1
nginx_ingress_controller_orphan_ingress{ingress="broken",namespace="shop",type="no-endpoint"} 1
nginx_ingress_controller_orphan_ingress{ingress="broken",namespace="shop",type="no-service"} 0
nginx_ingress_controller_orphan_ingress{ingress="quiet",namespace="shop",type="no-endpoint"} 0
nginx_ingress_controller_orphan_ingress{ingress="quiet",namespace="shop",type="no-service"} 0
`
	r := feed(t, c, pods, body, time.Unix(1_789_000_000, 0))

	byName := map[string]ingressRouteState{}
	for _, route := range r.Routes {
		byName[route.Name] = route
	}
	if byName["broken"].Orphaned == nil || *byName["broken"].Orphaned != "no-endpoint" {
		t.Fatalf("orphan not reported: %v", byName["broken"].Orphaned)
	}
	// A value of 0 is the controller saying "not orphaned", not a verdict.
	if byName["quiet"].Orphaned != nil {
		t.Fatalf("a healthy idle route was flagged orphaned: %v", *byName["quiet"].Orphaned)
	}

	var orphans float64
	var found bool
	for _, m := range c.emitIngress(r, time.Now()) {
		if m.Name == "k8s_ingress_orphaned_routes" {
			orphans, found = m.Value, true
		}
	}
	if !found || orphans != 1 {
		t.Fatalf("k8s_ingress_orphaned_routes = %v (found=%v), want 1", orphans, found)
	}
}

// With more controller replicas than the scrape cap, the same replicas are
// scraped regardless of input order, so rates keep their baselines.
func TestControllerCapIsAppliedAfterSorting(t *testing.T) {
	var pods []Pod
	bodies := map[string]string{}
	for i := range maxIngressControllers + 4 {
		ip := "10.0.1." + itoa(i)
		pods = append(pods, ingressControllerPod("c"+itoa(100+i), ip))
		bodies[ip] = ingressBody("1", "1", "1", "1", "1", "0")
	}
	scraped := func(order []Pod) map[string]bool {
		c := NewCollector("prod-cluster")
		c.ingresses = testReflector()
		c.scraper = fakeScraper(bodies)
		got := map[string]bool{}
		for _, ctl := range c.collectIngress(t.Context(), order, time.Unix(1_789_000_000, 0)).Controllers {
			got[ctl.Pod] = true
		}
		return got
	}
	forward := scraped(pods)
	reversed := make([]Pod, len(pods))
	for i, p := range pods {
		reversed[len(pods)-1-i] = p
	}
	backward := scraped(reversed)
	if len(forward) != maxIngressControllers {
		t.Fatalf("scraped %d controllers, want the cap %d", len(forward), maxIngressControllers)
	}
	for pod := range forward {
		if !backward[pod] {
			t.Fatalf("the scraped subset depends on store order: %v vs %v", forward, backward)
		}
	}
}

// Baselines of a controller replica that has gone, and of an ingress a live
// replica stops reporting, are pruned; an unreachable replica keeps its own.
func TestIngressBaselinesArePruned(t *testing.T) {
	c := NewCollector("prod-cluster")
	c.ingresses = testReflector()
	now := time.Unix(1_789_000_000, 0)
	pods := []Pod{ingressControllerPod("c1", "10.0.0.1"), ingressControllerPod("c2", "10.0.0.2")}
	feed(t, c, pods, ingressBody("1", "1", "1", "1", "1", "0"), now)
	if len(c.ingressLast) != 2 {
		t.Fatalf("expected one baseline per replica, got %v", c.ingressLast)
	}

	// c2 is rolled away; c1 answers with nothing for shop/web.
	c.scraper = fakeScraper(map[string]string{"10.0.0.1": "nginx_ingress_controller_build_info 1\n"})
	c.collectIngress(t.Context(), pods[:1], now.Add(time.Minute))
	if len(c.ingressLast) != 0 {
		t.Fatalf("stale baselines kept: %v", c.ingressLast)
	}

	// An unreachable replica's baseline survives for when it answers again.
	feed(t, c, pods[:1], ingressBody("1", "1", "1", "1", "1", "0"), now.Add(2*time.Minute))
	c.scraper = fakeScraper(nil)
	c.collectIngress(t.Context(), pods[:1], now.Add(3*time.Minute))
	if len(c.ingressLast) != 1 {
		t.Fatalf("an unreachable replica lost its baseline: %v", c.ingressLast)
	}
}
