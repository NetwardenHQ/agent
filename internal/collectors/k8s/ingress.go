package k8s

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

/*
Ingress traffic: bandwidth in and out, request rate, errors and latency, per
ingress and rolled up for the cluster.

There are two sources, as with CloudNativePG:

  - The Ingress objects are the route inventory: which ingresses exist, the
    hostnames they answer for, and whether they terminate TLS. The controller's
    exporter knows nothing about an ingress that has served no requests, so
    without this list an idle route would be invisible rather than idle.
  - The ingress-nginx controller pod exports the traffic counters on :10254.
    That is the only place the byte counts live.

The exporter is scraped over the pod network by IP, so the only grant needed
is read access to `networking.k8s.io/ingresses`; `pods/proxy` is not required.

The controller must have metrics enabled. ingress-nginx serves /metrics on the
same port as /healthz whether or not its own collectors are registered, so an
installation with metrics switched off answers 200 with nothing but Go runtime
series. That case is reported as metricsEnabled=false, not as zero traffic.
*/

const (
	ingressesPath = "/apis/networking.k8s.io/v1/ingresses"

	// ingress-nginx serves healthz and metrics on the same port.
	ingressMetricsPort = 10254

	// How many individual ingresses get their own time series. Same reasoning
	// as topPodSeries: the per-ingress labels are unbounded over time, and the
	// cluster rollups are what alerts are built on.
	topIngressSeries = 10

	// Hard ceiling on controller replicas scraped per cycle.
	maxIngressControllers = 8
)

// ingress-nginx labels its controller pods this way. Both are checked: the
// name alone also matches the admission webhook and the default-backend.
const (
	ingressControllerNameLabel      = "app.kubernetes.io/name"
	ingressControllerComponentLabel = "app.kubernetes.io/component"
	ingressControllerName           = "ingress-nginx"
	ingressControllerComponent      = "controller"
	ingressControllerVersionLabel   = "app.kubernetes.io/version"
)

// ingressWanted is the series lifted out of the controller exporter.
//
// The byte counts are the `_sum` component of a histogram, which is an ordinary
// monotonic counter of bytes, which is what a bandwidth figure needs. The
// `_bucket` lines are omitted: they are the bulk of the page and nothing here
// plots a distribution.
var ingressWanted = map[string]bool{
	"nginx_ingress_controller_requests":                       true,
	"nginx_ingress_controller_request_size_sum":               true,
	"nginx_ingress_controller_response_size_sum":              true,
	"nginx_ingress_controller_request_duration_seconds_sum":   true,
	"nginx_ingress_controller_request_duration_seconds_count": true,
	"nginx_ingress_controller_nginx_process_connections":      true,
	"nginx_ingress_controller_config_last_reload_successful":  true,
	"nginx_ingress_controller_build_info":                     true,
	"nginx_ingress_controller_orphan_ingress":                 true,
}

// ingressRouteState is one Ingress object plus whatever the controller has
// measured for it.
type ingressRouteState struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Class     string   `json:"class,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	TLS       bool     `json:"tls"`
	// Rates are interval deltas, so they are absent until a second scrape has
	// happened, and absent rather than zero when the controller exports no
	// metrics: "no traffic" and "not measured" are different claims.
	RequestsPerSecond *float64 `json:"requests_per_second,omitempty"`
	BytesInPerSecond  *float64 `json:"bytes_in_per_second,omitempty"`
	BytesOutPerSecond *float64 `json:"bytes_out_per_second,omitempty"`
	ErrorsPerSecond   *float64 `json:"errors_per_second,omitempty"`
	AvgDurationMs     *float64 `json:"avg_duration_ms,omitempty"`
	// Orphaned is the controller's own verdict that this ingress points at
	// nothing ("no-service" or "no-endpoint"). Such a route serves errors while
	// looking identical to a quiet one in a bandwidth panel. Absent when
	// healthy.
	Orphaned *string `json:"orphaned,omitempty"`
}

// ingressControllerState is one controller replica.
type ingressControllerState struct {
	Namespace      string `json:"namespace"`
	Pod            string `json:"pod"`
	Version        string `json:"version,omitempty"`
	Reachable      bool   `json:"reachable"`
	MetricsEnabled bool   `json:"metrics_enabled"`
	// A failed config reload means nginx is still serving the last good
	// config, so new ingresses silently do not take effect. Nil when unknown:
	// a controller with metrics switched off publishes no reload status, and
	// reporting that as false would flag a healthy controller as broken.
	ConfigReloadOK     *bool    `json:"config_reload_ok,omitempty"`
	ConnectionsActive  *float64 `json:"connections_active,omitempty"`
	ConnectionsWaiting *float64 `json:"connections_waiting,omitempty"`
}

type ingressReport struct {
	Cluster string `json:"cluster"`
	// False when no controller exports the nginx collectors.
	MetricsEnabled bool                     `json:"metrics_enabled"`
	Controllers    []ingressControllerState `json:"controllers"`
	Routes         []ingressRouteState      `json:"routes"`
	// Cluster rollups.
	RequestsPerSecond *float64 `json:"requests_per_second,omitempty"`
	BytesInPerSecond  *float64 `json:"bytes_in_per_second,omitempty"`
	BytesOutPerSecond *float64 `json:"bytes_out_per_second,omitempty"`
	ErrorsPerSecond   *float64 `json:"errors_per_second,omitempty"`
}

// ingressCounters is one controller replica's previous reading for one
// ingress.
//
// Keyed per controller pod. Each replica keeps its own counters, so a restart
// resets only that replica's; summing first and then differencing would make
// the total jump backwards and discard every other replica's reading. Deltas
// are taken per pod and then added up.
type ingressCounters struct {
	when        time.Time
	requests    float64
	errors      float64
	bytesIn     float64
	bytesOut    float64
	durationSum float64
	durationCnt float64
}

// collectIngress folds the Ingress inventory together with a scrape of every
// ingress-nginx controller replica.
func (c *Collector) collectIngress(ctx context.Context, pods []Pod, now time.Time) ingressReport {
	out := ingressReport{Cluster: c.clusterName}

	var controllers []Pod
	for _, p := range pods {
		l := p.Metadata.Labels
		if l[ingressControllerNameLabel] != ingressControllerName ||
			l[ingressControllerComponentLabel] != ingressControllerComponent {
			continue
		}
		if p.Status.PodIP == "" || p.Status.Phase != "Running" {
			continue
		}
		controllers = append(controllers, p)
	}
	// Sort before capping so a cluster with more replicas than the cap scrapes
	// the same ones every cycle. The store's iteration order is random, and a
	// changing subset would leave every rate without a baseline.
	sort.Slice(controllers, func(i, j int) bool {
		return podRef(controllers[i]) < podRef(controllers[j])
	})
	if len(controllers) > maxIngressControllers {
		controllers = controllers[:maxIngressControllers]
	}

	ingresses := c.ingresses.store.list()
	if len(controllers) == 0 && len(ingresses) == 0 {
		// This cluster does not route HTTP through an ingress at all.
		return out
	}

	results := make([][]promSample, len(controllers))
	errs := make([]error, len(controllers))
	sem := make(chan struct{}, cnpgScrapeConcurrency)
	var wg sync.WaitGroup
	for i, p := range controllers {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], errs[i] = c.scrapeExporter(ctx, ip, ingressMetricsPort, ingressWanted)
		}(i, p.Status.PodIP)
	}
	wg.Wait()

	// Per-ingress rate accumulators, summed from per-replica deltas.
	type acc struct {
		requests, errors, bytesIn, bytesOut float64
		durationSum, durationCnt            float64
		seen                                bool
	}
	rates := map[string]*acc{}
	get := func(k string) *acc {
		if rates[k] == nil {
			rates[k] = &acc{}
		}
		return rates[k]
	}
	// Orphan verdicts are gauges, not counters, so they are read fresh each
	// cycle rather than differenced. Any replica reporting one is enough.
	orphaned := map[string]string{}

	c.mu.Lock()
	if c.ingressLast == nil {
		c.ingressLast = map[string]ingressCounters{}
	}
	// Baselines refreshed this cycle, and the replicas that could not be read
	// (whose baselines are kept for when they answer again).
	refreshed := map[string]bool{}
	keep := map[string]bool{}

	for i, p := range controllers {
		st := ingressControllerState{
			Namespace: p.Metadata.Namespace,
			Pod:       p.Metadata.Name,
			Version:   p.Metadata.Labels[ingressControllerVersionLabel],
		}
		if errs[i] != nil {
			keep[podRef(p)] = true
			c.logger.Debug("kubernetes: ingress controller exporter unreachable",
				"pod", p.Metadata.Name, "error", errs[i],
				"hint", "a NetworkPolicy may be blocking the agent from the pod network")
			out.Controllers = append(out.Controllers, st)
			continue
		}
		st.Reachable = true

		cur := map[string]*ingressCounters{}
		curOf := func(k string) *ingressCounters {
			if cur[k] == nil {
				cur[k] = &ingressCounters{when: now}
			}
			return cur[k]
		}

		for _, s := range results[i] {
			switch s.Name {
			case "nginx_ingress_controller_build_info":
				// Present only when the nginx collectors are registered, which
				// is exactly the "metrics are switched on" signal.
				st.MetricsEnabled = true
			case "nginx_ingress_controller_config_last_reload_successful":
				ok := s.Value == 1
				st.ConfigReloadOK = &ok
				st.MetricsEnabled = true
			case "nginx_ingress_controller_nginx_process_connections":
				st.MetricsEnabled = true
				switch s.Labels["state"] {
				case "active":
					if st.ConnectionsActive == nil {
						st.ConnectionsActive = ptrFloat(0)
					}
					*st.ConnectionsActive += s.Value
				case "waiting":
					if st.ConnectionsWaiting == nil {
						st.ConnectionsWaiting = ptrFloat(0)
					}
					*st.ConnectionsWaiting += s.Value
				}
			case "nginx_ingress_controller_orphan_ingress":
				st.MetricsEnabled = true
				if s.Value == 1 {
					if t := s.Labels["type"]; t != "" {
						orphaned[ingressKey(s.Labels)] = t
					}
				}
			case "nginx_ingress_controller_requests":
				st.MetricsEnabled = true
				k := ingressKey(s.Labels)
				curOf(k).requests += s.Value
				// 5xx only. A 404 is the caller's mistake, and counting it as
				// an ingress error makes every public endpoint look broken.
				if strings.HasPrefix(s.Labels["status"], "5") {
					curOf(k).errors += s.Value
				}
			case "nginx_ingress_controller_request_size_sum":
				st.MetricsEnabled = true
				curOf(ingressKey(s.Labels)).bytesIn += s.Value
			case "nginx_ingress_controller_response_size_sum":
				st.MetricsEnabled = true
				curOf(ingressKey(s.Labels)).bytesOut += s.Value
			case "nginx_ingress_controller_request_duration_seconds_sum":
				st.MetricsEnabled = true
				curOf(ingressKey(s.Labels)).durationSum += s.Value
			case "nginx_ingress_controller_request_duration_seconds_count":
				st.MetricsEnabled = true
				curOf(ingressKey(s.Labels)).durationCnt += s.Value
			}
		}
		if st.MetricsEnabled {
			out.MetricsEnabled = true
		}
		out.Controllers = append(out.Controllers, st)

		for k, v := range cur {
			cacheKey := podRef(p) + "|" + k
			prev, had := c.ingressLast[cacheKey]
			c.ingressLast[cacheKey] = *v
			refreshed[cacheKey] = true
			if !had {
				continue
			}
			secs := now.Sub(prev.when).Seconds()
			if secs <= 0 {
				continue
			}
			// A counter that went backwards means this replica restarted. Its
			// delta is dropped; the other replicas' deltas still count.
			if v.requests < prev.requests || v.bytesIn < prev.bytesIn || v.bytesOut < prev.bytesOut {
				continue
			}
			a := get(k)
			a.seen = true
			a.requests += (v.requests - prev.requests) / secs
			a.bytesIn += (v.bytesIn - prev.bytesIn) / secs
			a.bytesOut += (v.bytesOut - prev.bytesOut) / secs
			if v.errors >= prev.errors {
				a.errors += (v.errors - prev.errors) / secs
			}
			if v.durationCnt > prev.durationCnt && v.durationSum >= prev.durationSum {
				a.durationSum += v.durationSum - prev.durationSum
				a.durationCnt += v.durationCnt - prev.durationCnt
			}
		}
	}
	// Drop baselines of replicas that are gone and of ingresses a replica has
	// stopped reporting; otherwise every rolled controller pod leaves its
	// table behind for the life of the agent.
	for k := range c.ingressLast {
		pod, _, _ := strings.Cut(k, "|")
		if !refreshed[k] && !keep[pod] {
			delete(c.ingressLast, k)
		}
	}
	c.mu.Unlock()

	sort.Slice(ingresses, func(i, j int) bool { return ingresses[i].key() < ingresses[j].key() })
	for _, ing := range ingresses {
		if c.skip(ing.Metadata.Namespace) {
			continue
		}
		r := ingressRouteState{
			Namespace: ing.Metadata.Namespace,
			Name:      ing.Metadata.Name,
			Class:     ing.Spec.IngressClassName,
			TLS:       len(ing.Spec.TLS) > 0,
		}
		for _, rule := range ing.Spec.Rules {
			if rule.Host != "" {
				r.Hosts = append(r.Hosts, rule.Host)
			}
		}
		if t, ok := orphaned[ing.Metadata.Namespace+"|"+ing.Metadata.Name]; ok {
			r.Orphaned = &t
		}
		if a, ok := rates[ing.Metadata.Namespace+"|"+ing.Metadata.Name]; ok && a.seen {
			r.RequestsPerSecond = ptrFloat(a.requests)
			r.BytesInPerSecond = ptrFloat(a.bytesIn)
			r.BytesOutPerSecond = ptrFloat(a.bytesOut)
			r.ErrorsPerSecond = ptrFloat(a.errors)
			if a.durationCnt > 0 {
				r.AvgDurationMs = ptrFloat(a.durationSum / a.durationCnt * 1000)
			}
		}
		out.Routes = append(out.Routes, r)
	}

	// Cluster rollups include every measured ingress, even one missing from
	// the inventory: traffic for an Ingress the agent cannot see still counts
	// towards the cluster's bandwidth.
	var measured bool
	var req, errRate, in, outB float64
	for _, a := range rates {
		if !a.seen {
			continue
		}
		measured = true
		req += a.requests
		errRate += a.errors
		in += a.bytesIn
		outB += a.bytesOut
	}
	if measured {
		out.RequestsPerSecond = ptrFloat(req)
		out.ErrorsPerSecond = ptrFloat(errRate)
		out.BytesInPerSecond = ptrFloat(in)
		out.BytesOutPerSecond = ptrFloat(outB)
	}

	return out
}

// podRef identifies a controller replica. Namespaced, because two ingress-nginx
// installations in different namespaces can have identically named pods.
func podRef(p Pod) string { return p.Metadata.Namespace + "/" + p.Metadata.Name }

// ingressKey identifies the ingress a sample belongs to. The exporter also
// carries host, path, method, service and status labels; folding them away here
// is what keeps the series count bounded.
func ingressKey(l map[string]string) string {
	return l["namespace"] + "|" + l["ingress"]
}

// topIngresses returns the n busiest by bytes moved, so the per-ingress series
// budget is spent on the routes anyone would look at.
func topIngresses(routes []ingressRouteState, n int) []ingressRouteState {
	measured := make([]ingressRouteState, 0, len(routes))
	for _, r := range routes {
		if r.BytesInPerSecond != nil || r.BytesOutPerSecond != nil {
			measured = append(measured, r)
		}
	}
	bytesOf := func(r ingressRouteState) float64 {
		var v float64
		if r.BytesInPerSecond != nil {
			v += *r.BytesInPerSecond
		}
		if r.BytesOutPerSecond != nil {
			v += *r.BytesOutPerSecond
		}
		return v
	}
	sort.Slice(measured, func(i, j int) bool {
		if bytesOf(measured[i]) != bytesOf(measured[j]) {
			return bytesOf(measured[i]) > bytesOf(measured[j])
		}
		return measured[i].Namespace+measured[i].Name < measured[j].Namespace+measured[j].Name
	})
	if len(measured) > n {
		measured = measured[:n]
	}
	return measured
}

// emitIngress turns the ingress report into series.
//
// Nothing is emitted when no controller exports metrics, or when the cluster
// has no ingress at all: a bandwidth gauge at zero would claim the cluster is
// serving no traffic, which is worse than a gap.
func (c *Collector) emitIngress(r ingressReport, now time.Time) []metrics.Metric {
	if !r.MetricsEnabled {
		return nil
	}

	out := make([]metrics.Metric, 0, 16)
	add := func(name string, v float64, labels map[string]string) {
		var m metrics.Metric
		var e error
		if labels == nil {
			m, e = c.builder.WithTimestamp(now).Gauge(name, v)
		} else {
			m, e = c.builder.WithTimestamp(now).GaugeWithLabels(name, v, labels)
		}
		if e == nil {
			out = append(out, m)
		}
	}

	if r.BytesInPerSecond != nil {
		add("k8s_ingress_bytes_in_per_second", *r.BytesInPerSecond, nil)
	}
	if r.BytesOutPerSecond != nil {
		add("k8s_ingress_bytes_out_per_second", *r.BytesOutPerSecond, nil)
	}
	if r.RequestsPerSecond != nil {
		add("k8s_ingress_requests_per_second", *r.RequestsPerSecond, nil)
	}
	if r.ErrorsPerSecond != nil {
		add("k8s_ingress_errors_per_second", *r.ErrorsPerSecond, nil)
	}
	add("k8s_ingress_routes_total", float64(len(r.Routes)), nil)

	// An ingress pointing at nothing serves errors while showing exactly the
	// same (absent) traffic as a quiet one, so it needs a series of its own.
	var orphans float64
	for _, route := range r.Routes {
		if route.Orphaned != nil {
			orphans++
		}
	}
	add("k8s_ingress_orphaned_routes", orphans, nil)

	var reloadFailures float64
	for _, ctl := range r.Controllers {
		// An unknown reload status is not a failure.
		if ctl.ConfigReloadOK != nil && !*ctl.ConfigReloadOK {
			reloadFailures++
		}
		l := map[string]string{"pod": ctl.Pod}
		if ctl.ConnectionsActive != nil {
			add("k8s_ingress_connections_active", *ctl.ConnectionsActive, l)
		}
		if ctl.ConnectionsWaiting != nil {
			add("k8s_ingress_connections_waiting", *ctl.ConnectionsWaiting, l)
		}
	}
	// A controller serving the last good config while rejecting new ones is
	// invisible in every traffic number, which is why it gets its own series.
	add("k8s_ingress_config_reload_failures", reloadFailures, nil)

	for _, route := range topIngresses(r.Routes, topIngressSeries) {
		l := map[string]string{"namespace": route.Namespace, "ingress": route.Name}
		if route.BytesInPerSecond != nil {
			add("k8s_ingress_route_bytes_in_per_second", *route.BytesInPerSecond, l)
		}
		if route.BytesOutPerSecond != nil {
			add("k8s_ingress_route_bytes_out_per_second", *route.BytesOutPerSecond, l)
		}
		if route.RequestsPerSecond != nil {
			add("k8s_ingress_route_requests_per_second", *route.RequestsPerSecond, l)
		}
		if route.ErrorsPerSecond != nil {
			add("k8s_ingress_route_errors_per_second", *route.ErrorsPerSecond, l)
		}
		if route.AvgDurationMs != nil {
			add("k8s_ingress_route_duration_ms", *route.AvgDurationMs, l)
		}
	}
	return out
}
