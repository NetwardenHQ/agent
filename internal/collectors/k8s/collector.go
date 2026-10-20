package k8s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// DefaultInterval is the collection cadence the registry drives (aligned with
// the global reporting interval). Health transitions are shipped on whichever
// cycle detects them; the background watchers keep the store current between
// cycles so detection latency is at most one interval.
const DefaultInterval = 60 * time.Second

// defaultReconcileInterval is how often the full cluster-health snapshot is
// emitted, as a periodic backstop to the real-time deltas. A cluster changes
// faster than a filesystem, so this is tighter than FIM's hourly walk.
const defaultReconcileInterval = 5 * time.Minute

// defaultComponentInterval is how often the component/version inventory is
// shipped. Images change rarely, so this is much slower than the health
// reconcile; version drift does not need minute-level latency.
const defaultComponentInterval = 15 * time.Minute

// defaultPendingThreshold is how long a pod may sit Pending before that is
// itself treated as a failure (a young Pending pod is merely starting up).
const defaultPendingThreshold = 5 * time.Minute

// Collector monitors the Kubernetes cluster the agent runs inside. Background
// reflectors keep an in-memory store of pods, nodes, and replicasets current by
// watching the API server; each Collect derives health, emits deltas for any
// transition since the last cycle, rolls failures up to their owning workload,
// and periodically ships a full cluster-health reconcile. It implements
// metrics.Collector and metrics.SnapshotProvider.
type Collector struct {
	hostname          string
	logger            *slog.Logger
	builder           metrics.MetricBuilder
	interval          time.Duration
	reconcileInterval time.Duration
	componentInterval time.Duration
	pendingThreshold  time.Duration
	clusterName       string
	cronJobs          *reflector[CronJob]
	lastCronSnapshot  time.Time
	// Capability switches; see WithCapabilities. Default true in NewCollector.
	capJobs         bool
	capAvailability bool
	capResources    bool
	capCNPG         bool
	capIngress      bool

	// CloudNativePG. The exporters live on the pod network, not behind the API
	// server, so they need an ordinary HTTP client of their own.
	cnpgClusters     *reflector[CNPGCluster]
	cnpgPoolers      *reflector[CNPGPooler]
	cnpgLast         map[string]cnpgCounters
	lastCNPGSnapshot time.Time
	scraper          *http.Client

	// Ingress. Counters are cached per controller replica (see ingressCounters).
	ingresses           *reflector[Ingress]
	ingressLast         map[string]ingressCounters
	lastIngressSnapshot time.Time

	cfg    *Config
	client *Client

	// watch lifecycle
	watchOnce    sync.Once
	watchCancel  context.CancelFunc
	watchers     sync.WaitGroup
	pods         *reflector[Pod]
	nodes        *reflector[Node]
	replicaSets  *reflector[ReplicaSet]
	jobs         *reflector[Job]
	deployments  *reflector[Deployment]
	statefulSets *reflector[StatefulSet]
	daemonSets   *reflector[DaemonSet]
	pdbs         *reflector[PodDisruptionBudget]
	endpoints    *reflector[EndpointSlice]
	// lastSync is the unix second the API server was last heard from by any
	// reflector. It answers "is the API reachable"; whether a particular store
	// is current is a separate question, answered per reflector (see fresh).
	lastSync atomic.Int64

	// excludedNamespaces is the namespace deny-list delivered from the UI via
	// /agent/config. A deny-list rather than an allow-list so that a namespace
	// created after the scope was last edited stays monitored by default. Atomic
	// because skip runs from scrape and usage paths that do not hold mu.
	excludedNamespaces atomic.Pointer[map[string]bool]

	mu               sync.Mutex
	serverVersion    string
	lastVersionCheck time.Time
	storageHistory   map[string][]storagePoint
	// rollingOutSince tracks when each workload started converging, so a rollout
	// that never finishes stops excusing the lost availability.
	rollingOutSince map[string]time.Time
	lastObserved    map[string]observation
	lastReconcile   time.Time
	lastComponents  time.Time
	pending         []metrics.Snapshot

	// noise policy state
	noise          noisePolicy
	unhealthySince map[string]time.Time
	lastNodeKeys   map[string]bool
	reclaimedAt    time.Time
	nodeCycles     atomic.Int64
}

// observation is the derived health of one object for a single cycle, carrying
// enough identity to build a delta and to report a later recovery.
type observation struct {
	key       string
	kind      string // pod | node
	namespace string
	name      string
	healthy   bool
	surface   bool
	reason    string
	message   string
	owner     string
	node      string
	count     int
	// Availability facts for workload observations. The agent ships these; the
	// server decides what severity they warrant.
	desired   int
	available int
}

// nsCounts is the per-namespace roll-up. Namespace is the granularity teams
// actually alert on; per-workload time series would cost ~20x for detail the
// findings already carry.
type nsCounts struct {
	podsRunning, podsPending, podsFailing int
	jobsFailing                           int
	workloadsDegraded                     int
}

// clusterCounts is the roll-up that feeds the reconcile snapshot and the
// dashboard metrics. fresh records which sections were derived from a current
// store; emitMetrics leaves every other section out.
type clusterCounts struct {
	fresh                                  freshness
	byNamespace                            map[string]*nsCounts
	nodesTotal, nodesReady, nodesPressured int
	podsRunning, podsPending, podsFailing  int
	jobsFailing                            int
	restarts                               int
	workloadsTotal                         int
	degraded                               []string
	suppressed                             int
}

// Option configures the collector.
type Option func(*Collector)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *Collector) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithConfig overrides in-cluster auto-detection (for out-of-cluster use or
// tests). When set, detection is skipped and this config is used verbatim.
func WithConfig(cfg Config) Option {
	return func(c *Collector) {
		cp := cfg
		c.cfg = &cp
	}
}

// WithInterval overrides the collection cadence.
func WithInterval(d time.Duration) Option {
	return func(c *Collector) {
		if d > 0 {
			c.interval = d
		}
	}
}

// WithReconcileInterval overrides how often the full cluster-health snapshot is
// emitted.
func WithReconcileInterval(d time.Duration) Option {
	return func(c *Collector) {
		if d > 0 {
			c.reconcileInterval = d
		}
	}
}

// Capabilities mirrors the optional permissions the install manifest granted.
// It is a struct rather than positional booleans so that a call site cannot
// silently transpose two of them.
type Capabilities struct {
	Jobs         bool
	Availability bool
	Resources    bool
	CNPG         bool
	Ingress      bool
}

// WithCapabilities restricts what the collector watches, mirroring the RBAC the
// install manifest granted. Anything switched off here has no permission in the
// cluster role either, so starting its watcher would only produce a 403 on
// every retry.
func WithCapabilities(caps Capabilities) Option {
	return func(c *Collector) {
		c.capJobs = caps.Jobs
		c.capAvailability = caps.Availability
		c.capResources = caps.Resources
		c.capCNPG = caps.CNPG
		c.capIngress = caps.Ingress
	}
}

// WithClusterName labels the cluster in emitted snapshots. Optional: it
// defaults to the agent hostname, which the install manifest sets to the
// cluster name.
func WithClusterName(name string) Option {
	return func(c *Collector) { c.clusterName = name }
}

// NewCollector builds the Kubernetes collector. If it cannot determine an
// in-cluster configuration (and none was supplied via WithConfig), the
// collector reports Enabled() == false and does nothing, which is the case on
// every host agent not running inside a cluster.
func NewCollector(hostname string, opts ...Option) *Collector {
	c := &Collector{
		hostname: hostname,
		// The install manifest sets `hostname:` to the cluster name, and the
		// server keys clusters on tenant and name, so an empty name would
		// never register a cluster. WithClusterName overrides this default.
		clusterName:     hostname,
		capJobs:         true,
		capAvailability: true,
		capResources:    true,
		capCNPG:         true,
		capIngress:      true,
		cnpgLast:        map[string]cnpgCounters{},
		ingressLast:     map[string]ingressCounters{},
		// Not the default client: no proxy, a hard timeout, kept-alive
		// connections so a 3-instance cluster does not reopen six sockets a
		// minute, and no redirects. An exporter is scraped at the pod IP the
		// API reported, and a 3xx must not send the agent anywhere else.
		scraper: &http.Client{
			Timeout: cnpgScrapeTimeout,
			Transport: &http.Transport{
				Proxy:               nil,
				MaxIdleConnsPerHost: cnpgScrapeConcurrency,
				IdleConnTimeout:     90 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		logger:            slog.Default(),
		builder:           metrics.NewBuilder().WithHostname(hostname),
		interval:          DefaultInterval,
		reconcileInterval: defaultReconcileInterval,
		componentInterval: defaultComponentInterval,
		pendingThreshold:  defaultPendingThreshold,
		lastObserved:      map[string]observation{},
		noise:             defaultNoisePolicy(),
		rollingOutSince:   map[string]time.Time{},
		unhealthySince:    map[string]time.Time{},
		lastNodeKeys:      map[string]bool{},
	}
	for _, o := range opts {
		o(c)
	}

	if c.cfg == nil {
		if cfg, ok := inClusterConfig(); ok {
			c.cfg = cfg
		}
	}
	if c.cfg != nil {
		client, err := NewClient(*c.cfg)
		if err != nil {
			c.logger.Warn("kubernetes: failed to build API client; collector inactive", "error", err)
			c.cfg = nil
		} else {
			c.client = client
			c.logger.Info("kubernetes: in-cluster configuration detected",
				"api", c.cfg.Host, "namespace", c.cfg.Namespace)
		}
	}
	return c
}

// SetExcludedNamespaces applies the namespace scope configured in the UI.
// It is called from the config poll; a nil or empty list means watch
// everything.
func (c *Collector) SetExcludedNamespaces(list []string) {
	set := make(map[string]bool, len(list))
	for _, n := range list {
		if n != "" {
			set[n] = true
		}
	}
	var old map[string]bool
	if p := c.excludedNamespaces.Swap(&set); p != nil {
		old = *p
	}
	changed := len(set) != len(old)
	if !changed {
		for n := range set {
			if !old[n] {
				changed = true
				break
			}
		}
	}
	if changed {
		c.logger.Info("kubernetes: namespace scope updated", "excluded", len(set))
	}
}

// SetThresholds applies the alerting patience configured in the UI. Zero or
// negative values keep the current setting.
func (c *Collector) SetThresholds(sustainedFor, rolloutGrace time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sustainedFor > 0 {
		c.noise.sustainedFor = sustainedFor
	}
	if rolloutGrace > 0 {
		c.noise.rolloutGrace = rolloutGrace
	}
}

// skip reports whether a namespaced object is out of scope. Cluster-scoped
// objects (nodes) are never skipped: they belong to no namespace and their
// health affects everything running on them.
func (c *Collector) skip(namespace string) bool {
	if namespace == "" {
		return false
	}
	excluded := c.excludedNamespaces.Load()
	return excluded != nil && (*excluded)[namespace]
}

// Name returns the collector name.
func (c *Collector) Name() string { return "kubernetes" }

// Enabled reports whether the agent is running inside a cluster (or was given
// an explicit config).
func (c *Collector) Enabled() bool { return c.client != nil }

// Close stops the background watchers, waits for them to exit, and drops the
// idle connections they and the exporter scrapes leave behind.
func (c *Collector) Close() error {
	c.mu.Lock()
	cancel := c.watchCancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.watchers.Wait()
	if c.scraper != nil {
		c.scraper.CloseIdleConnections()
	}
	if c.client != nil {
		c.client.list.CloseIdleConnections()
	}
	return nil
}

// initialSyncTimeout bounds the wait for the reflectors' first LIST. Generous
// enough for a large cluster, short enough that a genuinely unreachable API
// still reports as unreachable on the same cycle rather than hanging it.
var initialSyncTimeout = 15 * time.Second

// waitForInitialSync blocks until every enabled core store has completed its
// first list, or the timeout elapses. Waiting for only the first store is not
// enough: the first reconcile would be built from whichever stores happened to
// be filled (zero pods, no pod targets), and the server resolves open
// findings from that reconcile.
func (c *Collector) waitForInitialSync(ctx context.Context, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for !c.coreSynced() && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// freshness records which stores were current this cycle. A store that has
// never listed, or that has neither an open watch nor word from the API server
// within three intervals, is stale: whatever it holds is empty or old, so every
// section derived from it is left out rather than reported as zeros. A pod list
// that keeps failing (no RBAC, a response over maxListBytes) must read as "pods
// unknown", not as "no pods are running".
type freshness struct {
	pods, nodes, replicaSets              bool
	deployments, statefulSets, daemonSets bool
	jobs, cronJobs, pdbs, endpoints       bool
	cnpgClusters, cnpgPoolers, ingresses  bool
	// core is true when every store an enabled capability needs for the
	// health model is current: the condition for a reconcile, whose
	// unhealthy_targets the server treats as the complete set of open problems.
	core bool
}

// workloads reports whether all three workload kinds are current.
func (f freshness) workloads() bool { return f.deployments && f.statefulSets && f.daemonSets }

// podView reports whether pod observations can be derived. A pod's verdict
// depends on its owner (resolved through the ReplicaSets) and on whether
// that owner is impacted, so the workload stores must be current too.
func (f freshness) podView() bool { return f.pods && f.replicaSets && f.workloads() }

// covers reports whether o's source store was current this cycle, i.e. whether
// o was re-derived rather than left over from an earlier cycle.
func (f freshness) covers(o observation) bool {
	switch o.kind {
	case "pod":
		return f.podView()
	case "node":
		return f.nodes
	case "job":
		return f.jobs
	case "workload":
		return f.workloads()
	case "pdb":
		return f.pdbs
	case "service":
		return f.endpoints
	}
	return true
}

// fresh evaluates every store against the staleness window. Reflectors for
// disabled capabilities never run, so they always read as stale.
func (c *Collector) fresh(now time.Time) freshness {
	window := 3 * c.interval
	f := freshness{
		pods:         c.pods.current(now, window),
		nodes:        c.nodes.current(now, window),
		replicaSets:  c.replicaSets.current(now, window),
		deployments:  c.deployments.current(now, window),
		statefulSets: c.statefulSets.current(now, window),
		daemonSets:   c.daemonSets.current(now, window),
		jobs:         c.jobs.current(now, window),
		cronJobs:     c.cronJobs.current(now, window),
		pdbs:         c.pdbs.current(now, window),
		endpoints:    c.endpoints.current(now, window),
		cnpgClusters: c.cnpgClusters.current(now, window),
		cnpgPoolers:  c.cnpgPoolers.current(now, window),
		ingresses:    c.ingresses.current(now, window),
	}
	f.core = f.podView() && f.nodes &&
		(!c.capJobs || f.jobs) &&
		(!c.capAvailability || (f.pdbs && f.endpoints))
	return f
}

// coreSynced reports whether every core store has listed at least once.
func (c *Collector) coreSynced() bool {
	synced := []time.Time{
		c.pods.lastSynced(), c.nodes.lastSynced(), c.replicaSets.lastSynced(),
		c.deployments.lastSynced(), c.statefulSets.lastSynced(), c.daemonSets.lastSynced(),
	}
	if c.capJobs {
		synced = append(synced, c.jobs.lastSynced())
	}
	if c.capAvailability {
		synced = append(synced, c.pdbs.lastSynced(), c.endpoints.lastSynced())
	}
	for _, at := range synced {
		if at.IsZero() {
			return false
		}
	}
	return true
}

// ensureWatchers starts the reflectors once and reports whether this call
// started them, since only the first cycle has to wait for the stores to fill.
func (c *Collector) ensureWatchers() bool {
	if c.client == nil {
		return false
	}
	started := false
	c.watchOnce.Do(func() {
		started = true
		ctx, cancel := context.WithCancel(context.Background())
		onSync := func() { c.lastSync.Store(time.Now().Unix()) }

		c.pods = newReflector(c.client, "/api/v1/pods",
			func(p Pod) string { return p.key() }, c.logger.With("watch", "pods"), onSync)
		c.nodes = newReflector(c.client, "/api/v1/nodes",
			func(n Node) string { return n.key() }, c.logger.With("watch", "nodes"), onSync)
		c.replicaSets = newReflector(c.client, "/apis/apps/v1/replicasets",
			func(r ReplicaSet) string { return r.key() }, c.logger.With("watch", "replicasets"), nil)
		c.jobs = newReflector(c.client, "/apis/batch/v1/jobs",
			func(j Job) string { return j.key() }, c.logger.With("watch", "jobs"), onSync)
		c.cronJobs = newReflector(c.client, "/apis/batch/v1/cronjobs",
			func(cj CronJob) string { return cj.key() }, c.logger.With("watch", "cronjobs"), onSync)
		c.deployments = newReflector(c.client, "/apis/apps/v1/deployments",
			func(d Deployment) string { return d.key() }, c.logger.With("watch", "deployments"), onSync)
		c.statefulSets = newReflector(c.client, "/apis/apps/v1/statefulsets",
			func(x StatefulSet) string { return x.key() }, c.logger.With("watch", "statefulsets"), onSync)
		c.daemonSets = newReflector(c.client, "/apis/apps/v1/daemonsets",
			func(d DaemonSet) string { return d.key() }, c.logger.With("watch", "daemonsets"), onSync)
		c.pdbs = newReflector(c.client, "/apis/policy/v1/poddisruptionbudgets",
			func(p PodDisruptionBudget) string { return p.key() }, c.logger.With("watch", "pdbs"), onSync)
		c.endpoints = newReflector(c.client, "/apis/discovery.k8s.io/v1/endpointslices",
			func(e EndpointSlice) string { return e.key() }, c.logger.With("watch", "endpointslices"), onSync)
		c.cnpgClusters = newReflector(c.client, cnpgClustersPath,
			func(x CNPGCluster) string { return x.key() }, c.logger.With("watch", "cnpgclusters"), onSync)
		c.cnpgPoolers = newReflector(c.client, cnpgPoolersPath,
			func(x CNPGPooler) string { return x.key() }, c.logger.With("watch", "cnpgpoolers"), nil)
		c.ingresses = newReflector(c.client, ingressesPath,
			func(x Ingress) string { return x.key() }, c.logger.With("watch", "ingresses"), onSync)

		c.mu.Lock()
		c.watchCancel = cancel
		c.mu.Unlock()

		// The reflectors are always built, even for disabled capabilities, so
		// their stores stay empty and every store.list() remains valid without
		// nil checks. Only the goroutines are conditional.
		run := func(f func(context.Context)) {
			c.watchers.Add(1)
			go func() {
				defer c.watchers.Done()
				f(ctx)
			}()
		}
		started := []string{"pods", "nodes", "replicasets", "deployments", "statefulsets", "daemonsets"}
		run(c.pods.run)
		run(c.nodes.run)
		run(c.replicaSets.run)
		run(c.deployments.run)
		run(c.statefulSets.run)
		run(c.daemonSets.run)
		if c.capJobs {
			run(c.jobs.run)
			run(c.cronJobs.run)
			started = append(started, "jobs", "cronjobs")
		}
		if c.capAvailability {
			run(c.pdbs.run)
			run(c.endpoints.run)
			started = append(started, "pdbs", "endpointslices")
		}
		if c.capCNPG {
			// These watch a CRD that may not exist. A cluster without
			// CloudNativePG answers 404, the reflector backs off, and the
			// store never syncs, so nothing is reported.
			run(c.cnpgClusters.run)
			run(c.cnpgPoolers.run)
			started = append(started, "cnpgclusters", "cnpgpoolers")
		}
		if c.capIngress {
			run(c.ingresses.run)
			started = append(started, "ingresses")
		}
		c.logger.Info("kubernetes: watchers started",
			"resources", strings.Join(started, ","),
			"jobs", c.capJobs, "availability", c.capAvailability,
			"resources_usage", c.capResources, "cloudnativepg", c.capCNPG,
			"ingress", c.capIngress)
	})
	return started
}

// Collect derives current health from the watched store, emits transition
// deltas and (periodically) a cluster-health reconcile as snapshots, and
// returns the dashboard metrics.
func (c *Collector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	if c.client == nil {
		return nil, nil
	}
	first := c.ensureWatchers()
	if first {
		// ensureWatchers returns as soon as the reflectors are launched, before
		// any initial LIST completes. Reachability and freshness derive from
		// those lists, so without this wait the first cycle after a start would
		// report the API as unreachable and every section as unknown for a
		// whole interval.
		c.waitForInitialSync(ctx, initialSyncTimeout)
	}
	now := time.Now()

	// Reachability derives from watcher activity (any reflector hearing from
	// the API server within a few intervals), so no extra probe is needed.
	reachable := 0.0
	if last := c.lastSync.Load(); last > 0 && now.Sub(time.Unix(last, 0)) < 3*c.interval {
		reachable = 1
	}
	fresh := c.fresh(now)

	// Each input is read only from a current store. A stale one contributes
	// nil, and diff carries its previous observations forward unchanged: an
	// empty cache is not evidence that everything in it recovered.
	var allPods []Pod
	if fresh.pods {
		allPods = c.pods.store.list()
	}
	var pods []Pod // pods for the health model, which also needs their owners
	if fresh.podView() {
		pods = allPods
	}
	var nodes []Node
	if fresh.nodes {
		nodes = c.nodes.store.list()
		c.trackNodeRemovals(nodes, now)
	}
	var jobs []Job
	if fresh.jobs {
		jobs = c.jobs.store.list()
	}

	// Normalize the three workload kinds into one availability view.
	var workloads []workloadState
	if fresh.workloads() {
		for _, d := range c.deployments.store.list() {
			workloads = append(workloads, workloadStateOfDeployment(d))
		}
		for _, x := range c.statefulSets.store.list() {
			workloads = append(workloads, workloadStateOfStatefulSet(x))
		}
		for _, d := range c.daemonSets.store.list() {
			workloads = append(workloads, workloadStateOfDaemonSet(d))
		}
	}

	var pdbs []PodDisruptionBudget
	if fresh.pdbs {
		pdbs = c.pdbs.store.list()
	}
	var services []serviceEndpoints
	if fresh.endpoints {
		services = aggregateEndpointSlices(c.endpoints.store.list())
	}

	obs, counts := c.observe(pods, nodes, jobs, workloads, pdbs, services, now)
	counts.fresh = fresh
	transitions := c.diff(obs, now, func(o observation) bool { return !fresh.covers(o) })

	var snaps []metrics.Snapshot
	if len(transitions) > 0 {
		snaps = append(snaps, c.deltaSnapshot(transitions, now))
	}

	// The reconcile is authoritative: the server resolves every open finding
	// whose target it does not list. It therefore ships only when every store
	// that can produce a target is current. A missing reconcile delays a
	// resolution; a partial one would close real findings.
	c.mu.Lock()
	reconcileDue := c.lastReconcile.IsZero() || now.Sub(c.lastReconcile) >= c.reconcileInterval
	c.mu.Unlock()
	if reachable == 1 && fresh.core && reconcileDue {
		snaps = append(snaps, c.reconcileSnapshot(counts, now))
		c.mu.Lock()
		c.lastReconcile = now
		c.mu.Unlock()
	}

	c.mu.Lock()
	componentsDue := c.lastComponents.IsZero() || now.Sub(c.lastComponents) >= c.componentInterval
	c.mu.Unlock()
	if reachable == 1 && fresh.podView() && componentsDue {
		snaps = append(snaps, c.componentSnapshot(pods, now))
		snaps = append(snaps, c.inventorySnapshot(pods, workloads, now))
		c.mu.Lock()
		c.lastComponents = now
		c.mu.Unlock()
	}

	if len(snaps) > 0 {
		c.mu.Lock()
		c.pending = append(c.pending, snaps...)
		c.mu.Unlock()
	}

	c.maybeLogVersion(ctx, now)
	// Resource usage is polled, not watched (metrics.k8s.io has no watch), and
	// is optional: a cluster without metrics-server still reports everything
	// else. It is skipped when the API looks unreachable, since the poll would
	// only repeat the same failure.
	var usage usageSnapshot
	if reachable == 1 && c.capResources {
		usage = c.collectUsage(ctx, nodes)
		usage.DatabaseMemoryPercent = databaseMemoryPercent(usage.AllPods, allPods)
		// Kubelet storage rides on the usage series and is discarded with them
		// when metrics-server is absent, so it is not polled in that case. It
		// walks the node list, so it also needs that store to be current.
		if usage.Available && fresh.nodes {
			usage.Storage = c.collectStorage(ctx, nodes)
		}
	}

	// CronJobs: a slow-moving inventory, so it rides the same throttle as the
	// namespace inventory rather than shipping a payload every cycle.
	var cronReport cronJobReport
	if reachable == 1 && fresh.cronJobs && fresh.jobs {
		cronReport = buildCronJobReport(c.clusterName,
			inScope(c, c.cronJobs.store.list(), func(cj CronJob) string { return cj.Metadata.Namespace }),
			inScope(c, jobs, func(j Job) string { return j.Metadata.Namespace }), now)
		if now.Sub(c.lastCronSnapshot) >= c.reconcileInterval {
			c.lastCronSnapshot = now
			c.mu.Lock()
			c.pending = append(c.pending, metrics.Snapshot{
				Type: metrics.SnapshotK8sCronJobs,
				Payload: map[string]any{
					"cluster":      cronReport.Cluster,
					"cronjobs":     cronReport.CronJobs,
					"evaluated_at": now.UTC().Format(time.RFC3339),
				},
			})
			c.mu.Unlock()
		}
	}

	// CloudNativePG: topology from the CRs plus a scrape of each instance and
	// pooler exporter. Like CronJobs this is a slow-moving inventory, so the
	// payload rides the reconcile throttle, but the scrape runs every cycle
	// because the per-database rates are interval deltas and need a fresh
	// baseline whether or not a snapshot ships. Pooler replicas are found
	// through the pod store, so it has to be current as well.
	var cnpg cnpgReport
	if reachable == 1 && fresh.cnpgClusters && fresh.cnpgPoolers && fresh.pods {
		cnpg = c.collectCNPG(ctx, allPods, now)
		if len(cnpg.Postgres) > 0 && now.Sub(c.lastCNPGSnapshot) >= c.reconcileInterval {
			c.lastCNPGSnapshot = now
			c.mu.Lock()
			c.pending = append(c.pending, metrics.Snapshot{
				Type: metrics.SnapshotK8sCNPG,
				Payload: map[string]any{
					"cluster":           cnpg.Cluster,
					"postgres_clusters": cnpg.Postgres,
					"evaluated_at":      now.UTC().Format(time.RFC3339),
				},
			})
			c.mu.Unlock()
		}
	}

	// Ingress follows the CNPG pattern: inventory from the API, traffic from
	// the controller's exporter scraped every cycle, payload on the reconcile
	// throttle.
	var ingress ingressReport
	if reachable == 1 && fresh.ingresses && fresh.pods {
		ingress = c.collectIngress(ctx, allPods, now)
		if len(ingress.Routes) > 0 && now.Sub(c.lastIngressSnapshot) >= c.reconcileInterval {
			c.lastIngressSnapshot = now
			c.mu.Lock()
			c.pending = append(c.pending, metrics.Snapshot{
				Type: metrics.SnapshotK8sIngress,
				Payload: map[string]any{
					"cluster":         ingress.Cluster,
					"metrics_enabled": ingress.MetricsEnabled,
					"controllers":     ingress.Controllers,
					"routes":          ingress.Routes,
					"evaluated_at":    now.UTC().Format(time.RFC3339),
				},
			})
			c.mu.Unlock()
		}
	}

	return c.emitMetrics(reachable, counts, usage, cronReport, cnpg, ingress, now), nil
}

// inScope drops the objects that live in an excluded namespace.
func inScope[T any](c *Collector, items []T, namespaceOf func(T) string) []T {
	out := make([]T, 0, len(items))
	for _, it := range items {
		if !c.skip(namespaceOf(it)) {
			out = append(out, it)
		}
	}
	return out
}

// trackNodeRemovals detects nodes that were present last cycle and are gone
// since. Each removal is treated as a reclaim: it opens the reclaim window that
// observe consults and is counted. This catches both watch DELETEs and re-list
// removals. It must be called only when the node store is current, or an empty
// stale cache would look like every node vanishing at once.
func (c *Collector) trackNodeRemovals(nodes []Node, now time.Time) {
	current := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		current[n.key()] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k := range c.lastNodeKeys {
		if !current[k] {
			removed++
		}
	}
	if removed > 0 {
		c.reclaimedAt = now
		c.nodeCycles.Add(int64(removed))
		c.logger.Info("kubernetes: node(s) cycled", "count", removed,
			"note", "transient pod churn suppressed for the reclaim window")
	}
	c.lastNodeKeys = current
}

// observe derives per-object health, the cluster roll-up, and, via the noise
// policy, the surface verdict (whether a bad state should open a finding).
//
// Workload availability is computed first because it decides whether a pod
// fault is worth surfacing. A crash-looping pod in a workload that still has
// every replica available is an anomaly, not an incident.
func (c *Collector) observe(
	pods []Pod, nodes []Node, jobs []Job, workloads []workloadState,
	pdbs []PodDisruptionBudget, services []serviceEndpoints, now time.Time,
) ([]observation, clusterCounts) {
	obs := make([]observation, 0, len(pods)+len(nodes)+len(jobs)+len(workloads))
	counts := clusterCounts{byNamespace: map[string]*nsCounts{}}
	// owners, impacted and degraded are keyed by the namespace-qualified
	// target: two teams can each run a Deployment called "api", and one of them
	// being down must not un-demote the other's pods.
	owners := map[string]bool{}
	degraded := map[string]bool{}

	c.mu.Lock()
	defer c.mu.Unlock()

	ns := func(name string) *nsCounts {
		if name == "" {
			name = "_cluster"
		}
		if counts.byNamespace[name] == nil {
			counts.byNamespace[name] = &nsCounts{}
		}
		return counts.byNamespace[name]
	}

	reclaimOpen := !c.reclaimedAt.IsZero() && now.Sub(c.reclaimedAt) < c.noise.reclaimWindow

	surfaceOf := func(key string, hs healthState) bool {
		if hs.healthy {
			delete(c.unhealthySince, key)
			return false
		}
		since, ok := c.unhealthySince[key]
		if !ok {
			since = now
			c.unhealthySince[key] = since
		}
		return c.noise.surface(hs.reason, now.Sub(since), reclaimOpen)
	}

	// Workloads first: they decide what a pod fault means.
	impacted := map[string]bool{}
	for _, w := range workloads {
		if c.skip(w.namespace) {
			continue
		}
		// Rollout clock: start it when convergence begins, clear it when done.
		rolloutExpired := false
		if w.rollingOut {
			since, ok := c.rollingOutSince[w.key()]
			if !ok {
				since = now
				c.rollingOutSince[w.key()] = since
			}
			rolloutExpired = now.Sub(since) >= c.noise.rolloutGrace
		} else {
			delete(c.rollingOutSince, w.key())
		}
		hs := workloadHealth(w, rolloutExpired)
		target := qualify(w.namespace, w.ref())
		owners[target] = true
		surface := surfaceOf(w.key(), hs)
		if !hs.healthy {
			impacted[target] = true
			ns(w.namespace).workloadsDegraded++
		}
		if surface {
			degraded[target] = true
		}
		obs = append(obs, observation{
			key: w.key(), kind: "workload", namespace: w.namespace, name: w.name,
			healthy: hs.healthy, surface: surface, reason: hs.reason, message: hs.message,
			owner: w.ref(), desired: w.desired, available: w.available,
		})
	}

	// Disruption budgets: the team's own declaration of acceptable impact.
	for _, p := range pdbs {
		if c.skip(p.Metadata.Namespace) {
			continue
		}
		hs := pdbHealth(p)
		ref := "PodDisruptionBudget/" + p.Metadata.Name
		target := qualify(p.Metadata.Namespace, ref)
		surface := surfaceOf(p.key(), hs)
		if !hs.healthy {
			impacted[target] = true
			ns(p.Metadata.Namespace).workloadsDegraded++
		}
		if !hs.healthy && !surface {
			counts.suppressed++
		}
		if surface {
			degraded[target] = true
		}
		obs = append(obs, observation{
			key: p.key(), kind: "pdb", namespace: p.Metadata.Namespace, name: p.Metadata.Name,
			healthy: hs.healthy, surface: surface, reason: hs.reason, message: hs.message,
			owner:   ref,
			desired: p.Status.DesiredHealthy, available: p.Status.CurrentHealthy,
		})
	}

	// Service endpoints: can traffic actually land?
	for _, sv := range services {
		if c.skip(sv.namespace) {
			continue
		}
		hs := endpointsHealth(sv)
		surface := surfaceOf(sv.key(), hs)
		if !hs.healthy && !surface {
			counts.suppressed++
		}
		if surface {
			degraded[qualify(sv.namespace, sv.ref())] = true
		}
		obs = append(obs, observation{
			key: sv.key(), kind: "service", namespace: sv.namespace, name: sv.name,
			healthy: hs.healthy, surface: surface, reason: hs.reason, message: hs.message,
			owner: sv.ref(), desired: sv.total, available: sv.ready,
		})
	}

	for _, n := range nodes {
		counts.nodesTotal++
		if nodeReady(n) {
			counts.nodesReady++
		}
		if nodePressured(n) {
			counts.nodesPressured++
		}
		hs := nodeHealth(n)
		surface := surfaceOf(n.key(), hs)
		if !hs.healthy && !surface {
			counts.suppressed++
		}
		obs = append(obs, observation{
			key: n.key(), kind: "node", name: n.Metadata.Name,
			healthy: hs.healthy, surface: surface, reason: hs.reason, message: hs.message,
			node: n.Metadata.Name,
		})
	}

	for _, p := range pods {
		if c.skip(p.Metadata.Namespace) {
			continue
		}
		hs, restarts := podHealth(p, now, c.pendingThreshold)
		counts.restarts += restarts
		nsc := ns(p.Metadata.Namespace)
		switch p.Status.Phase {
		case "Running":
			counts.podsRunning++
			nsc.podsRunning++
		case "Pending":
			counts.podsPending++
			nsc.podsPending++
		}
		if !hs.healthy {
			counts.podsFailing++
			nsc.podsFailing++
		}

		owner := workloadOwner(p, c.replicaSets.store)
		target := qualify(p.Metadata.Namespace, owner)
		if owner != "" {
			owners[target] = true
		}

		surface := surfaceOf(p.key(), hs)
		// A pod fault only surfaces when its workload is impacted. If the
		// workload still has every replica available, the pod is being
		// replaced. A pod with no controller has no availability to fall back
		// on, so it stands alone.
		if surface && owner != "" && !impacted[target] {
			surface = false
		}
		if !hs.healthy && !surface {
			counts.suppressed++
		}

		obs = append(obs, observation{
			key: p.key(), kind: "pod", namespace: p.Metadata.Namespace, name: p.Metadata.Name,
			healthy: hs.healthy, surface: surface, reason: hs.reason, message: hs.message,
			owner: owner, node: p.Spec.NodeName, count: restarts,
		})
	}

	superseded := supersededJobs(jobs)
	for _, j := range jobs {
		if c.skip(j.Metadata.Namespace) {
			continue
		}
		hs := jobHealth(j)
		if !hs.healthy && superseded[j.key()] {
			hs = healthState{healthy: true}
		}
		surface := surfaceOf(j.key(), hs)
		if !hs.healthy {
			counts.jobsFailing++
			ns(j.Metadata.Namespace).jobsFailing++
		}
		if !hs.healthy && !surface {
			counts.suppressed++
		}
		owner := jobOwner(j)
		if owner != "" {
			target := qualify(j.Metadata.Namespace, owner)
			owners[target] = true
			if surface {
				degraded[target] = true
			}
		}
		obs = append(obs, observation{
			key: j.key(), kind: "job", namespace: j.Metadata.Namespace, name: j.Metadata.Name,
			healthy: hs.healthy, surface: surface, reason: hs.reason, message: hs.message,
			owner: owner,
		})
	}

	counts.workloadsTotal = len(owners)
	for w := range degraded {
		counts.degraded = append(counts.degraded, w)
	}
	sort.Strings(counts.degraded)
	return obs, counts
}

// diff compares this cycle's observations against the last, returning the
// transitions to ship: newly unhealthy, changed-reason, and recoveries
// (including objects that vanished while unhealthy), and updates the baseline.
//
// carry, when non-nil, marks previous observations whose source store was not
// current this cycle. Those are kept in the baseline as they were instead of
// being read as "vanished, so recovered".
func (c *Collector) diff(obs []observation, now time.Time, carry func(observation) bool) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()

	var transitions []map[string]any
	current := make(map[string]observation, len(obs))
	for _, o := range obs {
		current[o.key] = o
		prev, existed := c.lastObserved[o.key]
		if o.surface {
			if !existed || !prev.surface || prev.reason != o.reason {
				transitions = append(transitions, deltaOf(o, "unhealthy", now))
			}
		} else if existed && prev.surface {
			transitions = append(transitions, deltaOf(o, "recovered", now))
		}
	}
	for key, prev := range c.lastObserved {
		if _, ok := current[key]; ok {
			continue
		}
		if carry != nil && carry(prev) {
			current[key] = prev
			continue
		}
		if prev.surface {
			// An object removed while unhealthy counts as recovered.
			transitions = append(transitions, deltaOf(prev, "recovered", now))
		}
	}
	c.lastObserved = current
	return transitions
}

// deltaOf renders one transition for the wire.
func deltaOf(o observation, state string, now time.Time) map[string]any {
	d := map[string]any{
		"kind":      o.kind,
		"target":    targetOf(o),
		"name":      o.name,
		"reason":    o.reason,
		"state":     state,
		"detected":  "watch",
		"timestamp": now.UTC().Format(time.RFC3339),
	}
	if o.namespace != "" {
		d["namespace"] = o.namespace
	}
	if o.message != "" {
		d["message"] = o.message
	}
	if o.owner != "" {
		d["owner"] = o.owner
	}
	if o.node != "" {
		d["node"] = o.node
	}
	if o.count > 0 {
		d["count"] = o.count
	}
	// Availability facts travel with the delta so the server, not the agent,
	// decides how severe this is.
	if o.desired > 0 {
		d["desired"] = o.desired
		d["available"] = o.available
	}
	return d
}

func (c *Collector) deltaSnapshot(transitions []map[string]any, now time.Time) metrics.Snapshot {
	return metrics.Snapshot{
		Type: metrics.SnapshotK8sHealthDelta,
		Payload: map[string]any{
			"cluster":      c.clusterName,
			"transitions":  transitions,
			"evaluated_at": now.UTC().Format(time.RFC3339),
		},
	}
}

func (c *Collector) componentSnapshot(pods []Pod, now time.Time) metrics.Snapshot {
	return metrics.Snapshot{
		Type: metrics.SnapshotK8sComponentVersions,
		Payload: map[string]any{
			"cluster":      c.clusterName,
			"k8s_version":  c.currentVersion(),
			"images":       c.componentInventory(pods),
			"evaluated_at": now.UTC().Format(time.RFC3339),
		},
	}
}

// maxInventoryWorkloads bounds the per-namespace workload list. The inventory
// exists so the settings UI can offer real names to configure against, not to
// be a complete object dump.
const maxInventoryWorkloads = 200

// inventorySnapshot reports what exists in the cluster so the platform can offer
// a namespace picker instead of a free-text box. It is a catalog, not
// telemetry, so it ships on a slow cadence. It ignores the namespace
// exclusions: an excluded namespace must stay in the picker so it can be
// included again.
func (c *Collector) inventorySnapshot(
	pods []Pod, workloads []workloadState, now time.Time,
) metrics.Snapshot {
	type nsEntry struct {
		pods      int
		workloads map[string]bool
	}
	byNs := map[string]*nsEntry{}
	get := func(name string) *nsEntry {
		if byNs[name] == nil {
			byNs[name] = &nsEntry{workloads: map[string]bool{}}
		}
		return byNs[name]
	}
	for _, p := range pods {
		get(p.Metadata.Namespace).pods++
	}
	for _, w := range workloads {
		e := get(w.namespace)
		if len(e.workloads) < maxInventoryWorkloads {
			// Unqualified: the list is already grouped by namespace, and the
			// settings UI stores overrides as (namespace, "Kind/name").
			e.workloads[w.ref()] = true
		}
	}

	names := make([]string, 0, len(byNs))
	for n := range byNs {
		names = append(names, n)
	}
	sort.Strings(names)

	list := make([]map[string]any, 0, len(names))
	for _, n := range names {
		e := byNs[n]
		wl := make([]string, 0, len(e.workloads))
		for w := range e.workloads {
			wl = append(wl, w)
		}
		sort.Strings(wl)
		list = append(list, map[string]any{
			"name":      n,
			"pods":      e.pods,
			"workloads": wl,
		})
	}

	return metrics.Snapshot{
		Type: metrics.SnapshotK8sInventory,
		Payload: map[string]any{
			"cluster":      c.clusterName,
			"namespaces":   list,
			"evaluated_at": now.UTC().Format(time.RFC3339),
		},
	}
}

func (c *Collector) reconcileSnapshot(counts clusterCounts, now time.Time) metrics.Snapshot {
	degraded := counts.degraded
	if degraded == nil {
		degraded = []string{}
	}
	return metrics.Snapshot{
		Type: metrics.SnapshotK8sClusterHealth,
		Payload: map[string]any{
			"cluster":           c.clusterName,
			"k8s_version":       c.currentVersion(),
			"nodes":             map[string]any{"total": counts.nodesTotal, "ready": counts.nodesReady, "pressured": counts.nodesPressured},
			"pods":              map[string]any{"running": counts.podsRunning, "pending": counts.podsPending, "failing": counts.podsFailing},
			"workloads":         map[string]any{"total": counts.workloadsTotal, "degraded": degraded},
			"unhealthy_targets": c.activeTargets(),
			"digest":            c.reconcileDigest(),
			"evaluated_at":      now.UTC().Format(time.RFC3339),
		},
	}
}

// reconcileDigest hashes the current health of every object (sorted) so the
// platform can skip an unchanged reconcile, as with FIM's rollup digest.
func (c *Collector) reconcileDigest() string {
	c.mu.Lock()
	keys := make([]string, 0, len(c.lastObserved))
	for k := range c.lastObserved {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		o := c.lastObserved[k]
		fmt.Fprintf(h, "%s=%t,%s\n", k, o.healthy, o.reason)
	}
	c.mu.Unlock()
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func (c *Collector) currentVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverVersion
}

func (c *Collector) emitMetrics(reachable float64, counts clusterCounts, usage usageSnapshot, cron cronJobReport, cnpg cnpgReport, ingress ingressReport, now time.Time) []metrics.Metric {
	out := make([]metrics.Metric, 0, 12)
	add := func(name string, v float64) {
		if m, e := c.builder.WithTimestamp(now).Gauge(name, v); e == nil {
			out = append(out, m)
		}
	}
	add("k8s_api_reachable", reachable)
	if reachable == 1 {
		// Each section is emitted only from a current store; see freshness.
		f := counts.fresh
		if f.nodes {
			add("k8s_nodes_total", float64(counts.nodesTotal))
			add("k8s_nodes_ready", float64(counts.nodesReady))
			add("k8s_nodes_pressured", float64(counts.nodesPressured))
			if m, e := c.builder.WithTimestamp(now).Counter("k8s_node_cycled_total", float64(c.nodeCycles.Load())); e == nil {
				out = append(out, m)
			}
		}
		if f.podView() {
			add("k8s_pods_running", float64(counts.podsRunning))
			add("k8s_pods_pending", float64(counts.podsPending))
			add("k8s_pods_failing", float64(counts.podsFailing))
			add("k8s_restarts_total", float64(counts.restarts))
		}
		if f.jobs {
			add("k8s_jobs_failing", float64(counts.jobsFailing))
		}
		// These three roll up every source, so they need all of them.
		if f.core {
			add("k8s_workloads_total", float64(counts.workloadsTotal))
			add("k8s_workloads_degraded", float64(len(counts.degraded)))
			add("k8s_findings_suppressed", float64(counts.suppressed))
		}

		// Per-namespace series are kept to a small set: namespace count times
		// these five stays affordable where per-workload series would not.
		addNs := func(name string, nsName string, v float64) {
			if m, e := c.builder.WithTimestamp(now).
				GaugeWithLabels(name, v, map[string]string{"namespace": nsName}); e == nil {
				out = append(out, m)
			}
		}
		nsWorkloads := f.workloads() && (!c.capAvailability || f.pdbs)
		for nsName, nc := range counts.byNamespace {
			if f.podView() {
				addNs("k8s_ns_pods_running", nsName, float64(nc.podsRunning))
				addNs("k8s_ns_pods_pending", nsName, float64(nc.podsPending))
				addNs("k8s_ns_pods_failing", nsName, float64(nc.podsFailing))
			}
			if f.jobs {
				addNs("k8s_ns_jobs_failing", nsName, float64(nc.jobsFailing))
			}
			if nsWorkloads {
				addNs("k8s_ns_workloads_degraded", nsName, float64(nc.workloadsDegraded))
			}
		}

		out = append(out, c.emitUsage(usage, now)...)

		// CronJob rollups. "failing" means the last run failed, not that a run
		// ever failed: a job that failed once last month and has succeeded
		// daily since is not a problem.
		if cc := countCronJobs(cron); cc.total > 0 {
			add("k8s_cronjobs_total", float64(cc.total))
			add("k8s_cronjobs_suspended", float64(cc.suspended))
			add("k8s_cronjobs_failing", float64(cc.failing))
			add("k8s_cronjobs_active", float64(cc.active))
			// Only explicitly labeled database backups count; hourly and weekly
			// application jobs must not inherit a daily-backup age threshold. A
			// suspended backup is retired on purpose and must not hold the alert
			// open, masking a live backup that is overdue.
			var oldestBackup *float64
			for _, job := range cron.CronJobs {
				if !job.DatabaseBackup || job.Suspended {
					continue
				}
				timestamp := job.LastSuccessful
				if timestamp == "" {
					timestamp = job.CreatedAt
				}
				if last, err := time.Parse(time.RFC3339, timestamp); err == nil {
					age := max(0, now.Sub(last).Seconds())
					if oldestBackup == nil || age > *oldestBackup {
						oldestBackup = ptrFloat(age)
					}
				}
			}
			if oldestBackup != nil {
				add("k8s_database_backup_max_age_seconds", *oldestBackup)
			}
		}

		out = append(out, c.emitCNPG(cnpg, now)...)
		out = append(out, c.emitIngress(ingress, now)...)
	}
	return out
}

// emitCNPG turns the CloudNativePG report into series.
//
// Nothing is emitted when the cluster runs no CNPG clusters: a gauge at zero
// would read as an outage rather than as "not applicable".
func (c *Collector) emitCNPG(r cnpgReport, now time.Time) []metrics.Metric {
	if len(r.Postgres) == 0 {
		return nil
	}

	out := make([]metrics.Metric, 0, 24)
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

	cc := countCNPG(r)
	add("k8s_cnpg_clusters_total", float64(cc.clusters), nil)
	add("k8s_cnpg_clusters_healthy", float64(cc.healthy), nil)
	add("k8s_cnpg_instances_total", float64(cc.instances), nil)
	add("k8s_cnpg_instances_ready", float64(cc.ready), nil)
	add("k8s_cnpg_poolers_total", float64(cc.poolers), nil)
	add("k8s_cnpg_instances_unreachable", float64(cc.unreachable), nil)
	var maxConnections *float64
	databaseDown := 0
	var maxPoolWait *float64
	unreachablePoolers := 0
	for _, cl := range r.Postgres {
		for _, inst := range cl.Instances {
			if inst.PostgresUp != nil && *inst.PostgresUp == 0 {
				databaseDown++
			}
			if inst.Reachable && inst.Backends != nil && inst.MaxConnections != nil && *inst.MaxConnections > 0 {
				pct := *inst.Backends / *inst.MaxConnections * 100
				if maxConnections == nil || pct > *maxConnections {
					maxConnections = ptrFloat(pct)
				}
			}
		}
		for _, p := range cl.Poolers {
			if !p.Reachable {
				if p.Scraped {
					unreachablePoolers++
				}
				continue
			}
			if maxPoolWait == nil || p.MaxWaitSeconds > *maxPoolWait {
				maxPoolWait = ptrFloat(p.MaxWaitSeconds)
			}
		}
	}
	add("k8s_cnpg_instances_database_down", float64(databaseDown), nil)
	if maxConnections != nil {
		add("k8s_cnpg_max_connections_percent", *maxConnections, nil)
	}
	if maxPoolWait != nil {
		add("k8s_cnpg_pooler_max_wait_seconds", *maxPoolWait, nil)
	}
	add("k8s_cnpg_poolers_unreachable", float64(unreachablePoolers), nil)

	for _, cl := range r.Postgres {
		l := cnpgLabels(cl)
		add("k8s_cnpg_cluster_healthy", boolValue(cl.Healthy), l)
		add("k8s_cnpg_cluster_instances_ready", float64(cl.InstancesReady), l)
		add("k8s_cnpg_cluster_instances_total", float64(cl.InstancesTotal), l)
		if cl.sizeMeasured {
			add("k8s_cnpg_cluster_size_bytes", cl.TotalSizeBytes, l)
		}
		if cl.MaxLagSeconds != nil {
			add("k8s_cnpg_replication_lag_seconds", *cl.MaxLagSeconds, l)
		}
		if cl.TransactionsSec != nil {
			add("k8s_cnpg_transactions_per_second", *cl.TransactionsSec, l)
		}

		for _, db := range cl.Databases {
			dl := cnpgLabels(cl, "database", db.Name)
			add("k8s_cnpg_database_size_bytes", db.SizeBytes, dl)
			if db.TransactionsPerSecond != nil {
				add("k8s_cnpg_database_transactions_per_second", *db.TransactionsPerSecond, dl)
			}
			if db.CacheHitRatio != nil {
				add("k8s_cnpg_database_cache_hit_ratio", *db.CacheHitRatio, dl)
			}
		}

		for _, p := range cl.Poolers {
			if !p.Reachable {
				continue // its counts were never measured
			}
			pl := cnpgLabels(cl, "pooler", p.Name)
			add("k8s_cnpg_pooler_clients_active", p.ClientsActive, pl)
			add("k8s_cnpg_pooler_clients_waiting", p.ClientsWaiting, pl)
			add("k8s_cnpg_pooler_servers_active", p.ServersActive, pl)
			if p.QueriesPerSecond != nil {
				add("k8s_cnpg_pooler_queries_per_second", *p.QueriesPerSecond, pl)
			}
			if p.AvgQueryTimeMs != nil {
				add("k8s_cnpg_pooler_query_time_ms", *p.AvgQueryTimeMs, pl)
			}
			if p.AvgWaitTimeMs != nil {
				add("k8s_cnpg_pooler_wait_time_ms", *p.AvgWaitTimeMs, pl)
			}
		}
	}
	return out
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// emitUsage turns one metrics.k8s.io poll into series.
//
// Nothing is emitted when metrics-server is absent: a cluster with no metrics
// API must show a gap, not a false flat line at zero.
func (c *Collector) emitUsage(u usageSnapshot, now time.Time) []metrics.Metric {
	if !u.Available {
		return nil
	}

	out := make([]metrics.Metric, 0, 32)
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

	add("k8s_cpu_cores_used", u.TotalCPUCores, nil)
	add("k8s_memory_bytes_used", u.TotalMemBytes, nil)
	if u.Storage.Collected {
		add("k8s_storage_nodes_unreachable", float64(u.Storage.FailedNodes), nil)
		add("k8s_storage_forecast_ready", float64(u.Storage.ForecastReady), nil)
		add("k8s_storage_exhaustion_within_7d", float64(u.Storage.ForecastAtRisk), nil)
	}
	if u.Storage.NodePercent != nil {
		add("k8s_node_max_disk_percent", *u.Storage.NodePercent, nil)
	}
	if u.Storage.PVCPercent != nil {
		add("k8s_pvc_max_disk_percent", *u.Storage.PVCPercent, nil)
	}
	if u.DatabaseMemoryPercent != nil {
		add("k8s_cnpg_max_memory_percent", *u.DatabaseMemoryPercent, nil)
	}
	if u.AllocCPUCores > 0 {
		add("k8s_cpu_cores_allocatable", u.AllocCPUCores, nil)
		add("k8s_cpu_usage_percent", u.TotalCPUCores/u.AllocCPUCores*100, nil)
	}
	if u.AllocMemBytes > 0 {
		add("k8s_memory_bytes_allocatable", u.AllocMemBytes, nil)
		add("k8s_memory_usage_percent", u.TotalMemBytes/u.AllocMemBytes*100, nil)
	}

	var maxNodeMemory *float64
	for _, n := range u.Nodes {
		if n.AllocMemBytes > 0 {
			pct := n.MemBytes / n.AllocMemBytes * 100
			if maxNodeMemory == nil || pct > *maxNodeMemory {
				maxNodeMemory = ptrFloat(pct)
			}
		}
	}
	if maxNodeMemory != nil {
		add("k8s_node_max_memory_percent", *maxNodeMemory, nil)
	}
	for _, n := range u.Nodes {
		l := map[string]string{"node": n.Name}
		add("k8s_node_cpu_cores", n.CPUCores, l)
		add("k8s_node_memory_bytes", n.MemBytes, l)
		// Percentages are against allocatable, which is what the scheduler
		// honors; capacity would understate pressure by the system reserve.
		if n.AllocCPUCores > 0 {
			add("k8s_node_cpu_percent", n.CPUCores/n.AllocCPUCores*100, l)
		}
		if n.AllocMemBytes > 0 {
			add("k8s_node_memory_percent", n.MemBytes/n.AllocMemBytes*100, l)
		}
		if n.StorageBytes > 0 {
			add("k8s_node_storage_capacity_bytes", n.StorageBytes, l)
		}
	}

	for ns, r := range u.ByNamespace {
		l := map[string]string{"namespace": ns}
		add("k8s_ns_cpu_cores", r.CPUCores, l)
		add("k8s_ns_memory_bytes", r.MemBytes, l)
	}

	for _, p := range u.TopPods {
		l := map[string]string{"namespace": p.Namespace, "pod": p.Name}
		add("k8s_pod_cpu_cores", p.CPUCores, l)
		add("k8s_pod_memory_bytes", p.MemBytes, l)
	}

	return out
}

// Snapshots returns the deltas and reconcile staged since the last call, then
// clears them.
func (c *Collector) Snapshots() []metrics.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return nil
	}
	out := c.pending
	c.pending = nil
	return out
}

// versionRefreshInterval is how often the API server version is re-read once
// known. It changes only on a control-plane upgrade.
const versionRefreshInterval = 15 * time.Minute

// maybeLogVersion fetches the server version and logs it once, and again only
// when it changes. It also feeds k8s_version in the reconcile snapshot. Until
// the first success it retries every cycle; after that, every
// versionRefreshInterval.
func (c *Collector) maybeLogVersion(ctx context.Context, now time.Time) {
	c.mu.Lock()
	due := c.serverVersion == "" || now.Sub(c.lastVersionCheck) >= versionRefreshInterval
	if due {
		c.lastVersionCheck = now
	}
	c.mu.Unlock()
	if !due {
		return
	}
	version, err := c.client.ServerVersion(ctx)
	if err != nil || version == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if version != c.serverVersion {
		c.serverVersion = version
		c.logger.Info("kubernetes: API server", "version", version)
	}
}

// targetOf returns the identity a finding is keyed on: the owning workload when
// known (so pod churn does not churn findings), else the object itself. It is
// namespace-qualified ("shop/Deployment/api"): the server fingerprints findings
// on it, and "Deployment/api" alone would merge two namespaces' workloads into
// one finding. The delta's separate `owner` field stays "Kind/name" because it
// travels next to `namespace`, and per-namespace mute/elevate settings match
// on that form.
func targetOf(o observation) string {
	if o.owner != "" {
		return qualify(o.namespace, o.owner)
	}
	return o.key
}

// qualify prefixes a "Kind/name" reference with its namespace. Cluster-scoped
// and empty references are returned unchanged.
func qualify(namespace, ref string) string {
	if namespace == "" || ref == "" {
		return ref
	}
	return namespace + "/" + ref
}

// activeTargets returns the sorted, de-duplicated set of targets currently
// unhealthy. The reconcile ships it so the server can authoritatively resolve
// any k8s finding whose target no longer appears.
func (c *Collector) activeTargets() []string {
	c.mu.Lock()
	seen := map[string]bool{}
	for _, o := range c.lastObserved {
		if o.surface {
			seen[targetOf(o)] = true
		}
	}
	c.mu.Unlock()
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

var (
	_ metrics.Collector        = (*Collector)(nil)
	_ metrics.SnapshotProvider = (*Collector)(nil)
)
