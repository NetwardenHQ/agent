package k8s

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/NetwardenHQ/agent/internal/spool"
)

/*
Following the ingress-nginx access log.

One follower per controller replica streams the controller container's log
through the API (pods/log, follow=true, timestamps=true). Replicas are taken
from the pod store, so a rollout is followed as it happens: a new replica is
read from its start, and a replica that goes away is dropped. A stream that
ends is resumed from the timestamp of the last line read; sinceTime has
one-second resolution, so the lines of that second come again and are
dropped by request id.

Time spent not following a running replica (connecting, refused, waiting for
a container to start) is reported as k8s_ingress_log_gap_seconds. The lines
of that time may still arrive once the stream resumes, unless the kubelet
rotated the log in between; the metric errs on the side of reporting.
*/

const (
	ingressLogContainer    = "controller"
	ingressLogRetryMin     = time.Second
	ingressLogRetryMax     = time.Minute
	ingressLogForbidden    = 5 * time.Minute
	ingressLogRecentIDs    = 4096
	ingressLogBufferBytes  = 64 << 10
	ingressLogReconcileGap = 15 * time.Second
)

type followerStats struct {
	Reading    bool
	Forbidden  bool
	Replicas   int
	GapSeconds float64
	// Full reports whether every line read since the last call was in the
	// JSON format; nil when no line was read.
	Full *bool
}

type logFollowers struct {
	client         *Client
	namespace      string
	tracker        *edgeTracker
	ownHosts       func() []string
	logger         *slog.Logger
	now            func() time.Time
	retryMin       time.Duration
	retryMax       time.Duration
	forbiddenRetry time.Duration
	started        time.Time

	ctx    context.Context
	cancel context.CancelFunc

	mu           sync.Mutex
	followers    map[string]*follower
	lastStats    time.Time
	fullLines    int
	defaultLines int
}

type follower struct {
	pod, container string
	podStart       time.Time
	cancel         context.CancelFunc

	mu        sync.Mutex
	up        bool
	downSince time.Time
	forbidden bool
	lastTime  time.Time
	seen      recentIDs
}

func newLogFollowers(client *Client, namespace string, tracker *edgeTracker, ownHosts func() []string, logger *slog.Logger) *logFollowers {
	ctx, cancel := context.WithCancel(context.Background())
	return &logFollowers{
		client:         client,
		namespace:      namespace,
		tracker:        tracker,
		ownHosts:       ownHosts,
		logger:         logger,
		now:            time.Now,
		retryMin:       ingressLogRetryMin,
		retryMax:       ingressLogRetryMax,
		forbiddenRetry: ingressLogForbidden,
		started:        time.Now(),
		ctx:            ctx,
		cancel:         cancel,
		followers:      map[string]*follower{},
	}
}

// Stop ends every follower.
func (f *logFollowers) Stop() { f.cancel() }

func isIngressController(p Pod, namespace string) bool {
	l := p.Metadata.Labels
	return p.Metadata.Namespace == namespace && p.Status.Phase == "Running" &&
		l[ingressControllerNameLabel] == ingressControllerName && l[ingressControllerComponentLabel] == ingressControllerComponent
}

// Reconcile starts a follower for every running controller replica in the
// namespace and stops the ones whose replica is gone.
func (f *logFollowers) Reconcile(pods []Pod) {
	want := map[string]Pod{}
	for _, p := range pods {
		if isIngressController(p, f.namespace) {
			want[p.Metadata.Name] = p
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, fl := range f.followers {
		if _, ok := want[name]; !ok {
			fl.cancel()
			delete(f.followers, name)
		}
	}
	for name, p := range want {
		if _, ok := f.followers[name]; ok {
			continue
		}
		container := ingressLogContainer
		if !hasContainer(p, container) && len(p.Spec.Containers) > 0 {
			container = p.Spec.Containers[0].Name
		}
		start, _ := time.Parse(time.RFC3339, p.Status.StartTime)
		ctx, cancel := context.WithCancel(f.ctx)
		fl := &follower{pod: name, container: container, podStart: start, cancel: cancel, downSince: f.now()}
		f.followers[name] = fl
		go f.follow(ctx, fl)
	}
}

func hasContainer(p Pod, name string) bool {
	for _, c := range p.Spec.Containers {
		if c.Name == name {
			return true
		}
	}
	return false
}

// run reconciles from the pod store between collection cycles, so a rollout
// is picked up in seconds rather than at the next report.
func (f *logFollowers) run(pods func() []Pod) {
	t := time.NewTicker(ingressLogReconcileGap)
	defer t.Stop()
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-t.C:
			if list := pods(); list != nil {
				f.Reconcile(list)
			}
		}
	}
}

// resumeFrom is where the next stream starts: after the last line read; for
// a replica that started after us, its beginning; otherwise now.
func (f *logFollowers) resumeFrom(fl *follower) time.Time {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if !fl.lastTime.IsZero() {
		return fl.lastTime
	}
	if fl.podStart.After(f.started) {
		return fl.podStart
	}
	return f.started
}

func (f *logFollowers) follow(ctx context.Context, fl *follower) {
	backoff := f.retryMin
	for ctx.Err() == nil {
		rc, err := f.client.FollowLog(ctx, f.namespace, fl.pod, fl.container, f.resumeFrom(fl))
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			forbidden := isForbidden(err)
			if fl.setDown(f.now(), forbidden) {
				f.logger.Warn("kubernetes: cannot read the ingress controller log", "pod", fl.pod, "error", err)
			}
			wait := backoff
			if forbidden {
				wait = f.forbiddenRetry
			}
			if !sleepCtx(ctx, wait) {
				return
			}
			backoff = min(backoff*2, f.retryMax)
			continue
		}
		if fl.setUp() {
			f.logger.Info("kubernetes: following the ingress controller log", "pod", fl.pod)
		}
		backoff = f.retryMin
		f.read(fl, rc)
		rc.Close()
		if ctx.Err() != nil {
			return
		}
		fl.setDown(f.now(), false)
		if !sleepCtx(ctx, f.retryMin) {
			return
		}
	}
}

func isForbidden(err error) bool {
	var se *apiStatusError
	return errors.As(err, &se) && (se.status == http.StatusForbidden || se.status == http.StatusUnauthorized)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (f *logFollowers) read(fl *follower, rc io.Reader) {
	br := bufio.NewReaderSize(rc, ingressLogBufferBytes)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Far longer than any access line: skip to its end.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			f.tracker.CountUnparsed()
			if err != nil {
				return
			}
			continue
		}
		if len(line) > 0 {
			f.handle(fl, line)
		}
		if err != nil {
			return
		}
	}
}

func (f *logFollowers) handle(fl *follower, line []byte) {
	if ts, _ := splitLogTimestamp(line); !ts.IsZero() {
		fl.mu.Lock()
		if ts.After(fl.lastTime) {
			fl.lastTime = ts
		}
		fl.mu.Unlock()
	}
	if len(line) <= 1 || IsControllerMessage(line) {
		return
	}
	l, ok := ParseAccessLine(line)
	if !ok {
		f.tracker.CountUnparsed()
		return
	}
	if l.RequestID != "" {
		fl.mu.Lock()
		fresh := fl.seen.add(l.RequestID)
		fl.mu.Unlock()
		if !fresh {
			return
		}
	}
	f.mu.Lock()
	if l.Full {
		f.fullLines++
	} else {
		f.defaultLines++
	}
	f.mu.Unlock()
	blind, _ := f.tracker.ServerActionBlind(l, l.Time)
	hosts := f.ownHosts()
	classes := Classify(l, hosts, blind)
	// The Host header is the client's to choose. Once the cluster's own host
	// names are known, a request naming anything else (a bare IP, someone
	// else's site) still counts, but not as one of your sites.
	if len(hosts) > 0 && !ownHost(l.Host, hosts) {
		l.Host = ""
	}
	f.tracker.Observe(l, classes)
}

// ownHost reports whether host (a Host header, maybe with a port) is one of
// the cluster's Ingress hosts; "*.example.com" covers one more label.
func ownHost(host string, hosts []string) bool {
	h := strings.ToLower(host)
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	if h == "" {
		return false
	}
	for _, own := range hosts {
		if suffix, wild := strings.CutPrefix(own, "*."); wild {
			if label, rest, ok := strings.Cut(h, "."); ok && label != "" && rest == suffix {
				return true
			}
		} else if h == own {
			return true
		}
	}
	return false
}

// Stats reports the followers since the previous call.
func (f *logFollowers) Stats(now time.Time) followerStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := followerStats{Replicas: len(f.followers)}
	up := 0
	names := make([]string, 0, len(f.followers))
	for name := range f.followers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fl := f.followers[name]
		fl.mu.Lock()
		if fl.up {
			up++
		} else {
			from := fl.downSince
			if f.lastStats.After(from) {
				from = f.lastStats
			}
			if gap := now.Sub(from).Seconds(); gap > st.GapSeconds {
				st.GapSeconds = gap
			}
		}
		st.Forbidden = st.Forbidden || fl.forbidden
		fl.mu.Unlock()
	}
	st.Reading = st.Replicas > 0 && up == st.Replicas
	if f.fullLines+f.defaultLines > 0 {
		full := f.defaultLines == 0
		st.Full = &full
	}
	f.fullLines, f.defaultLines = 0, 0
	f.lastStats = now
	return st
}

// setDown marks the stream down; true when that is news.
func (fl *follower) setDown(at time.Time, forbidden bool) bool {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	news := fl.up || fl.forbidden != forbidden || fl.downSince.IsZero()
	if fl.up || fl.downSince.IsZero() {
		fl.downSince = at
	}
	fl.up, fl.forbidden = false, forbidden
	return news
}

// setUp marks the stream open; true when that is news.
func (fl *follower) setUp() bool {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	news := !fl.up
	fl.up, fl.forbidden = true, false
	return news
}

// recentIDs remembers the last ingressLogRecentIDs request ids.
type recentIDs struct {
	ring []string
	next int
	set  map[string]struct{}
}

// add records id; false when it was already there.
func (r *recentIDs) add(id string) bool {
	if r.set == nil {
		r.set = make(map[string]struct{}, ingressLogRecentIDs)
		r.ring = make([]string, ingressLogRecentIDs)
	}
	if _, ok := r.set[id]; ok {
		return false
	}
	if old := r.ring[r.next]; old != "" {
		delete(r.set, old)
	}
	r.ring[r.next] = id
	r.set[id] = struct{}{}
	r.next = (r.next + 1) % len(r.ring)
	return true
}

// maxBlindSeries bounds the per-ingress server-action series.
const maxBlindSeries = 50

// startIngressLogs begins following the controller log. It needs somewhere
// to put events: without a spool directory the capability reports that it
// is not reading.
func (c *Collector) startIngressLogs() {
	if c.spoolDir == "" {
		return
	}
	logger := c.logger.With("watch", "ingress-log")
	edge := loadEdgeTracker(c.spoolDir, maxTrackedAddresses, logger)
	edge.urgent = c.urgent
	logs := newLogFollowers(c.client, c.ingressLogNamespace, edge, c.ownHosts, logger)
	c.mu.Lock()
	c.edge, c.logs = edge, logs
	c.mu.Unlock()
	c.refreshOwnHosts()
	go logs.run(c.controllerPods)
}

// controllerPods is the pod store for the followers, or nil while it is not
// current (an empty stale store is not evidence that the controllers left).
func (c *Collector) controllerPods() []Pod {
	if !c.pods.current(time.Now(), 3*c.interval) {
		return nil
	}
	c.refreshOwnHosts()
	return c.pods.store.list()
}

// ownHosts is the cluster's Ingress host names (wildcards included), for
// targeted_path and for telling your sites from whatever a client claims.
// It is read for every log line, so it serves a cached copy.
func (c *Collector) ownHosts() []string {
	if p := c.ownHostsCache.Load(); p != nil {
		return *p
	}
	return nil
}

func (c *Collector) refreshOwnHosts() {
	if c.ingresses == nil {
		return
	}
	seen := map[string]bool{}
	var hosts []string
	for _, ing := range c.ingresses.store.list() {
		for _, r := range ing.Spec.Rules {
			if h := strings.ToLower(r.Host); h != "" && !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	sort.Strings(hosts)
	c.ownHostsCache.Store(&hosts)
}

func (c *Collector) warnOnce(key, msg string, args ...any) {
	c.mu.Lock()
	seen := c.edgeWarned[key]
	c.edgeWarned[key] = true
	c.mu.Unlock()
	if !seen {
		c.logger.Warn(msg, args...)
	}
}

// collectEdge closes the cycle's windows, spools the events and reports how
// the reading is going.
func (c *Collector) collectEdge(fresh freshness, pods []Pod, now time.Time) []metrics.Metric {
	if !c.capIngressLogs {
		return nil
	}
	var out []metrics.Metric
	add := func(name string, v float64, labels map[string]string) {
		b := c.builder.WithTimestamp(now)
		var m metrics.Metric
		var err error
		if labels == nil {
			m, err = b.Gauge(name, v)
		} else {
			m, err = b.GaugeWithLabels(name, v, labels)
		}
		if err == nil {
			out = append(out, m)
		}
	}

	c.mu.Lock()
	edge, logs := c.edge, c.logs
	c.mu.Unlock()
	if logs == nil {
		c.warnOnce("no-spool", "kubernetes: reading the ingress log needs a spool directory for its events; not reading it",
			"spool_dir", c.spoolDir)
		add("k8s_ingress_log_reading", 0, nil)
		return out
	}

	c.refreshOwnHosts()
	if fresh.pods {
		logs.Reconcile(pods)
	}
	probes, exposures, stats := edge.Flush(now)
	st := logs.Stats(now)
	if st.Replicas == 0 {
		c.warnOnce("no-controller", "kubernetes: no running ingress-nginx controller found; not reading its log",
			"namespace", c.ingressLogNamespace)
	}
	for _, batch := range []struct {
		name   string
		events []spool.Event
	}{{"edge-exposure", exposures}, {"edge", probes}} {
		if len(batch.events) == 0 {
			continue
		}
		if err := spool.WriteEvents(c.spoolDir, fmt.Sprintf("%s-%d", batch.name, now.UnixNano()), batch.events); err != nil {
			c.logger.Warn("kubernetes: could not spool ingress log events", "events", len(batch.events), "error", err)
		}
	}
	if err := edge.Save(c.spoolDir); err != nil {
		c.warnOnce("save", "kubernetes: could not save what the ingress log taught; it is relearned after a restart", "error", err)
	}

	reading := 0.0
	if st.Reading {
		reading = 1
	}
	add("k8s_ingress_log_reading", reading, nil)
	if st.Full != nil {
		full := 0.0
		if *st.Full {
			full = 1
		}
		add("k8s_ingress_log_full_format", full, nil)
	}
	add("k8s_ingress_log_lines", float64(stats.Lines), nil)
	add("k8s_ingress_log_unparsed", float64(stats.Unparsed), nil)
	add("k8s_ingress_log_gap_seconds", st.GapSeconds, nil)
	add("k8s_ingress_log_sources_flagged", float64(stats.Flagged), nil)
	add("k8s_ingress_log_sources_dropped", float64(stats.Dropped), nil)
	for i, b := range edge.BlindIngresses(now) {
		if i >= maxBlindSeries {
			break
		}
		v, reason := 0.0, "none"
		if b.Reason != "" {
			v, reason = 1, b.Reason
		}
		add("k8s_ingress_log_server_action_blind", v, map[string]string{"ingress": b.Ingress, "reason": reason})
	}
	return out
}
