package k8s

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

/*
CloudNativePG reporting: cluster topology, who is primary, per-database
throughput and size, and connection-pooler behavior.

Two sources, because neither alone is enough:

  - The Cluster custom resource carries the topology: desired and ready
    instance counts, which instance the operator considers primary, the
    timeline, and each instance's pod IP. None of that is in the metrics.
  - Each instance pod runs CloudNativePG's exporter on :9187, and each pooler
    pod runs the pgbouncer exporter on :9127. That is where throughput,
    database size, replication lag and pool saturation live. None of that is in
    the CR.

The exporters are scraped over the pod network by IP, not through the API
server's `/proxy` subresource. The proxy would need `pods/proxy` in the cluster
role, which grants GET on any port of any pod in the cluster, a much larger
permission than "read two exporters". The agent runs inside the cluster, so the
pod IPs are directly routable.

Neither exporter requires authentication. If a NetworkPolicy blocks the hop the
scrape fails, the instance is reported with up=false, and the topology (from the
CR) is still reported: a partial view, clearly marked, rather than nothing.
*/

const (
	cnpgClustersPath = "/apis/postgresql.cnpg.io/v1/clusters"
	cnpgPoolersPath  = "/apis/postgresql.cnpg.io/v1/poolers"

	// CloudNativePG's fixed exporter ports.
	cnpgInstanceMetricsPort = 9187
	cnpgPoolerMetricsPort   = 9127

	// Per-endpoint budget. An exporter that has to be waited on is an exporter
	// that is not going to answer: it queries a local Postgres over a unix
	// socket, so a healthy scrape is single-digit milliseconds.
	cnpgScrapeTimeout = 4 * time.Second

	// How many exporters are scraped at once. Enough to keep a large fleet
	// inside one collection interval without opening a connection per pod.
	cnpgScrapeConcurrency = 6

	// Hard ceiling on endpoints per cycle. A cluster with hundreds of CNPG
	// instances would otherwise spend the whole interval scraping; the
	// topology still reports in full, only the per-instance readings stop.
	cnpgMaxScrapes = 48

	// The label CloudNativePG puts on every pooler's pods.
	cnpgPoolerNameLabel = "cnpg.io/poolerName"
)

// CNPGCluster is the subset of a CloudNativePG Cluster resource the collector
// reads.
type CNPGCluster struct {
	Metadata ObjectMeta        `json:"metadata"`
	Spec     CNPGClusterSpec   `json:"spec"`
	Status   CNPGClusterStatus `json:"status"`
}

func (c CNPGCluster) key() string {
	return "cnpgcluster|" + c.Metadata.Namespace + "|" + c.Metadata.Name
}

// CNPGClusterSpec is the desired state of a CNPGCluster.
type CNPGClusterSpec struct {
	Instances int    `json:"instances,omitempty"`
	ImageName string `json:"imageName,omitempty"`
}

// CNPGClusterStatus is the operator-reported state of a CNPGCluster.
type CNPGClusterStatus struct {
	Phase          string   `json:"phase,omitempty"`
	Instances      int      `json:"instances,omitempty"`
	ReadyInstances int      `json:"readyInstances,omitempty"`
	CurrentPrimary string   `json:"currentPrimary,omitempty"`
	TargetPrimary  string   `json:"targetPrimary,omitempty"`
	InstanceNames  []string `json:"instanceNames,omitempty"`
	TimelineID     int      `json:"timelineID,omitempty"`
	Image          string   `json:"image,omitempty"`
	WriteService   string   `json:"writeService,omitempty"`
	ReadService    string   `json:"readService,omitempty"`
	// instancesStatus buckets instance names by condition: "healthy",
	// "replicating", "failed", ... The operator adds buckets over time, so this
	// is read as a map rather than named fields.
	InstancesStatus map[string][]string `json:"instancesStatus,omitempty"`
	// instancesReportedState is the only place the instance pod IPs appear.
	InstancesReportedState map[string]CNPGInstanceState `json:"instancesReportedState,omitempty"`
	PGDataImageInfo        struct {
		MajorVersion int `json:"majorVersion,omitempty"`
	} `json:"pgDataImageInfo,omitempty"`
}

// CNPGInstanceState is the operator's last reported state for one instance.
type CNPGInstanceState struct {
	IP         string `json:"ip,omitempty"`
	IsPrimary  bool   `json:"isPrimary,omitempty"`
	TimeLineID int    `json:"timeLineID,omitempty"`
}

// CNPGPooler is the subset of a CloudNativePG Pooler resource the collector
// reads.
type CNPGPooler struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Instances *int   `json:"instances,omitempty"`
		Type      string `json:"type,omitempty"` // rw (default) | ro
		Cluster   struct {
			Name string `json:"name"`
		} `json:"cluster"`
	} `json:"spec"`
	Status struct {
		Instances int    `json:"instances,omitempty"`
		Phase     string `json:"phase,omitempty"`
	} `json:"status"`
}

func (p CNPGPooler) key() string {
	return "cnpgpooler|" + p.Metadata.Namespace + "|" + p.Metadata.Name
}

// cnpgInstanceState is one Postgres instance: its role from the operator, its
// health from the operator, and its readings from its own exporter.
type cnpgInstanceState struct {
	Name       string `json:"name"`
	Role       string `json:"role"` // primary | replica
	Healthy    bool   `json:"healthy"`
	TimelineID int    `json:"timeline_id,omitempty"`
	// Scraped reports whether the exporter was asked at all this cycle: an
	// instance with no pod IP, or one past cnpgMaxScrapes, is not. Reachable
	// reports whether it answered. The readings below are absent unless both
	// hold, and an unscraped instance is not counted as unreachable.
	Scraped           bool     `json:"scraped"`
	Reachable         bool     `json:"reachable"`
	PostgresVersion   string   `json:"postgres_version,omitempty"`
	InRecovery        bool     `json:"in_recovery"`
	LagSeconds        *float64 `json:"lag_seconds,omitempty"`
	StreamingReplicas *float64 `json:"streaming_replicas,omitempty"`
	SlotsActive       *float64 `json:"replication_slots_active,omitempty"`
	Backends          *float64 `json:"backends,omitempty"`
	PostgresUp        *float64 `json:"postgres_up,omitempty"`
	MaxConnections    *float64 `json:"max_connections,omitempty"`
	LongestTxSeconds  *float64 `json:"longest_transaction_seconds,omitempty"`
}

// cnpgDatabaseState is one database inside a CNPG cluster, read from the
// primary's exporter.
type cnpgDatabaseState struct {
	Name      string  `json:"name"`
	SizeBytes float64 `json:"size_bytes"`
	// Rates are per-interval deltas, so they are unknown until a second poll
	// has happened. Absent rather than zero: "no traffic" and "not measured
	// yet" are different claims and a monitoring product must not conflate
	// them.
	TransactionsPerSecond *float64 `json:"transactions_per_second,omitempty"`
	RollbacksPerSecond    *float64 `json:"rollbacks_per_second,omitempty"`
	TuplesReadPerSecond   *float64 `json:"tuples_read_per_second,omitempty"`
	CacheHitRatio         *float64 `json:"cache_hit_ratio,omitempty"`
	Deadlocks             float64  `json:"deadlocks"`
	Backends              float64  `json:"backends"`
}

// cnpgPoolerState is one pgbouncer pooler, summed across its replicas.
type cnpgPoolerState struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Cluster   string `json:"cluster"`
	Type      string `json:"type"` // rw | ro
	Phase     string `json:"phase,omitempty"`
	Instances int    `json:"instances"`
	// Scraped and Reachable mean what they do on an instance. The counts below
	// are zero, not measured, when the pooler was not reached.
	Scraped   bool   `json:"scraped"`
	Reachable bool   `json:"reachable"`
	PoolMode  string `json:"pool_mode,omitempty"`
	// pgbouncer already publishes these as per-second averages over its own
	// stats period, so they need no rate computation here.
	QueriesPerSecond *float64 `json:"queries_per_second,omitempty"`
	AvgQueryTimeMs   *float64 `json:"avg_query_time_ms,omitempty"`
	AvgWaitTimeMs    *float64 `json:"avg_wait_time_ms,omitempty"`
	ClientsActive    float64  `json:"clients_active"`
	ClientsWaiting   float64  `json:"clients_waiting"`
	ServersActive    float64  `json:"servers_active"`
	ServersIdle      float64  `json:"servers_idle"`
	MaxWaitSeconds   float64  `json:"max_wait_seconds"`
}

type cnpgClusterState struct {
	Namespace      string   `json:"namespace"`
	Name           string   `json:"name"`
	Phase          string   `json:"phase,omitempty"`
	Healthy        bool     `json:"healthy"`
	Primary        string   `json:"primary,omitempty"`
	SwitchoverTo   string   `json:"switchover_to,omitempty"`
	InstancesReady int      `json:"instances_ready"`
	InstancesTotal int      `json:"instances_total"`
	TimelineID     int      `json:"timeline_id,omitempty"`
	Image          string   `json:"image,omitempty"`
	PostgresMajor  int      `json:"postgres_major,omitempty"`
	WriteService   string   `json:"write_service,omitempty"`
	ReadService    string   `json:"read_service,omitempty"`
	MaxLagSeconds  *float64 `json:"max_lag_seconds,omitempty"`
	TotalSizeBytes float64  `json:"total_size_bytes"`
	// sizeMeasured is true when TotalSizeBytes was read from the primary's
	// exporter; otherwise it is a zero that must not become a series.
	sizeMeasured    bool
	TransactionsSec *float64            `json:"transactions_per_second,omitempty"`
	Instances       []cnpgInstanceState `json:"instances"`
	Databases       []cnpgDatabaseState `json:"databases"`
	Poolers         []cnpgPoolerState   `json:"poolers"`
}

type cnpgReport struct {
	Cluster  string             `json:"cluster"`
	Postgres []cnpgClusterState `json:"postgres_clusters"`
}

// cnpgWantedInstance / cnpgWantedPooler are the series lifted out of each
// exporter. Naming them explicitly keeps the parser allocation-free on the
// thousands of lines that are not needed.
var cnpgWantedInstance = map[string]bool{
	"cnpg_pg_settings_setting":               true,
	"cnpg_collector_up":                      true,
	"cnpg_last_update_timestamp":             true,
	"cnpg_collector_postgres_version":        true,
	"cnpg_pg_replication_lag":                true,
	"cnpg_pg_replication_in_recovery":        true,
	"cnpg_pg_replication_streaming_replicas": true,
	"cnpg_pg_replication_slots_active":       true,
	"cnpg_backends_total":                    true,
	"cnpg_backends_max_tx_duration_seconds":  true,
	"cnpg_pg_database_size_bytes":            true,
	"cnpg_pg_stat_database_xact_commit":      true,
	"cnpg_pg_stat_database_xact_rollback":    true,
	"cnpg_pg_stat_database_tup_returned":     true,
	"cnpg_pg_stat_database_blks_hit":         true,
	"cnpg_pg_stat_database_blks_read":        true,
	"cnpg_pg_stat_database_deadlocks":        true,
	"cnpg_pg_stat_database_numbackends":      true,
}

var cnpgWantedPooler = map[string]bool{
	"cnpg_pgbouncer_stats_avg_query_count": true,
	"cnpg_pgbouncer_stats_avg_query_time":  true,
	"cnpg_pgbouncer_stats_avg_wait_time":   true,
	"cnpg_pgbouncer_pools_cl_active":       true,
	"cnpg_pgbouncer_pools_cl_waiting":      true,
	"cnpg_pgbouncer_pools_sv_active":       true,
	"cnpg_pgbouncer_pools_sv_idle":         true,
	"cnpg_pgbouncer_pools_maxwait":         true,
	"cnpg_pgbouncer_pools_pool_mode":       true,
}

// pgbouncer reports pool_mode as an enum. The mapping is pgbouncer's own
// ordering (statement, transaction, session); anything else is left unnamed
// rather than guessed at.
var cnpgPoolModes = map[float64]string{1: "statement", 2: "transaction", 3: "session"}

// cnpgCounters is the previous reading of the monotonic per-database counters,
// kept so the next poll can turn them into rates.
//
// `when` is the exporter's own snapshot time, not the poll time. The
// CloudNativePG exporter refreshes its Postgres readings on an internal cycle
// (~40s, measured) and serves the cached values in between, so two polls 60s
// apart may be 39s apart in the data. Dividing by the wall clock would
// understate every rate by that difference, and two polls that land on the
// same cached snapshot would report a flat zero: a false "no traffic" on a
// busy database.
type cnpgCounters struct {
	when      time.Time
	commits   float64
	rollbacks float64
	tupReturn float64
	blksHit   float64
	blksRead  float64
}

// scrapeExporter fetches one exporter's /metrics and returns only the wanted
// series.
func (c *Collector) scrapeExporter(ctx context.Context, ip string, port int, want map[string]bool) ([]promSample, error) {
	if ip == "" {
		return nil, fmt.Errorf("no pod IP")
	}
	ctx, cancel := context.WithTimeout(ctx, cnpgScrapeTimeout)
	defer cancel()

	url := "http://" + net.JoinHostPort(ip, fmt.Sprint(port)) + "/metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.scraper.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exporter %s: status %d", url, resp.StatusCode)
	}
	// Read one byte past the cap so an oversized page is an error rather than
	// a silently truncated, and therefore partial, set of samples.
	body := &countingReader{r: io.LimitReader(resp.Body, maxExporterBytes+1)}
	samples, err := parsePromText(body, want)
	if err != nil {
		return nil, fmt.Errorf("exporter %s: %w", url, err)
	}
	if body.n > maxExporterBytes {
		return nil, fmt.Errorf("exporter %s: response larger than %d MiB", url, maxExporterBytes>>20)
	}
	return samples, nil
}

// maxExporterBytes caps one exporter page. A real CNPG or ingress-nginx page is
// well under 1 MiB even on a busy cluster; anything past this is not a
// recognized exporter, and reading it unbounded would let any pod on the
// network grow the agent's memory.
const maxExporterBytes = 8 << 20

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// collectCNPG folds the Cluster CRs together with a scrape of every instance
// and pooler exporter.
//
// A scrape failure is never fatal: the topology from the CR is the part someone
// pages on ("we have no primary"), and it is available without touching a
// single exporter.
func (c *Collector) collectCNPG(ctx context.Context, pods []Pod, now time.Time) cnpgReport {
	clusters := c.cnpgClusters.store.list()
	if len(clusters) == 0 {
		return cnpgReport{Cluster: c.clusterName}
	}
	poolers := c.cnpgPoolers.store.list()

	// Index pooler pods by the pooler they belong to, so each pooler's replicas
	// can be scraped without another API call.
	poolerPods := map[string][]Pod{}
	for _, p := range pods {
		name := p.Metadata.Labels[cnpgPoolerNameLabel]
		if name == "" || p.Status.PodIP == "" || p.Status.Phase != "Running" {
			continue
		}
		k := p.Metadata.Namespace + "/" + name
		poolerPods[k] = append(poolerPods[k], p)
	}

	// Plan every scrape up front so the ceiling applies across the whole
	// cluster fleet rather than per cluster.
	type target struct {
		clusterIdx int
		instance   string // empty for a pooler target
		poolerKey  string
		ip         string
		port       int
		want       map[string]bool
	}
	var targets []target

	out := cnpgReport{Cluster: c.clusterName, Postgres: make([]cnpgClusterState, 0, len(clusters))}

	sort.Slice(clusters, func(i, j int) bool { return clusters[i].key() < clusters[j].key() })
	for _, cl := range clusters {
		if c.skip(cl.Metadata.Namespace) {
			continue
		}
		st := cnpgClusterState{
			Namespace:      cl.Metadata.Namespace,
			Name:           cl.Metadata.Name,
			Phase:          cl.Status.Phase,
			Primary:        cl.Status.CurrentPrimary,
			InstancesReady: cl.Status.ReadyInstances,
			InstancesTotal: cl.Status.Instances,
			TimelineID:     cl.Status.TimelineID,
			Image:          cl.Status.Image,
			PostgresMajor:  cl.Status.PGDataImageInfo.MajorVersion,
			WriteService:   cl.Status.WriteService,
			ReadService:    cl.Status.ReadService,
		}
		if st.InstancesTotal == 0 {
			st.InstancesTotal = cl.Spec.Instances
		}
		if st.Image == "" {
			st.Image = cl.Spec.ImageName
		}
		// A pending switchover is worth surfacing on its own: the cluster can
		// read "healthy" while the operator is mid-promotion.
		if cl.Status.TargetPrimary != "" && cl.Status.TargetPrimary != cl.Status.CurrentPrimary {
			st.SwitchoverTo = cl.Status.TargetPrimary
		}
		st.Healthy = st.InstancesTotal > 0 && st.InstancesReady == st.InstancesTotal &&
			st.Primary != "" && st.SwitchoverTo == ""

		healthy := map[string]bool{}
		for _, n := range cl.Status.InstancesStatus["healthy"] {
			healthy[n] = true
		}

		names := cl.Status.InstanceNames
		if len(names) == 0 {
			for n := range cl.Status.InstancesReportedState {
				names = append(names, n)
			}
		}
		sort.Strings(names)

		idx := len(out.Postgres)
		for _, n := range names {
			rs := cl.Status.InstancesReportedState[n]
			inst := cnpgInstanceState{
				Name:       n,
				Role:       "replica",
				Healthy:    healthy[n],
				TimelineID: rs.TimeLineID,
			}
			if rs.IsPrimary || n == cl.Status.CurrentPrimary {
				inst.Role = "primary"
			}
			st.Instances = append(st.Instances, inst)
			if rs.IP != "" && len(targets) < cnpgMaxScrapes {
				st.Instances[len(st.Instances)-1].Scraped = true
				targets = append(targets, target{
					clusterIdx: idx, instance: n, ip: rs.IP,
					port: cnpgInstanceMetricsPort, want: cnpgWantedInstance,
				})
			}
		}

		for _, pl := range poolers {
			if pl.Metadata.Namespace != cl.Metadata.Namespace || pl.Spec.Cluster.Name != cl.Metadata.Name {
				continue
			}
			ps := cnpgPoolerState{
				Namespace: pl.Metadata.Namespace,
				Name:      pl.Metadata.Name,
				Cluster:   cl.Metadata.Name,
				Type:      pl.Spec.Type,
				Phase:     pl.Status.Phase,
				Instances: pl.Status.Instances,
			}
			if ps.Type == "" {
				ps.Type = "rw" // the operator's own default when unset
			}
			if ps.Instances == 0 && pl.Spec.Instances != nil {
				ps.Instances = *pl.Spec.Instances
			}
			key := pl.Metadata.Namespace + "/" + pl.Metadata.Name
			for _, pod := range poolerPods[key] {
				if len(targets) >= cnpgMaxScrapes {
					break
				}
				ps.Scraped = true
				targets = append(targets, target{
					clusterIdx: idx, poolerKey: key, ip: pod.Status.PodIP,
					port: cnpgPoolerMetricsPort, want: cnpgWantedPooler,
				})
			}
			st.Poolers = append(st.Poolers, ps)
		}
		sort.Slice(st.Poolers, func(i, j int) bool { return st.Poolers[i].Name < st.Poolers[j].Name })
		out.Postgres = append(out.Postgres, st)
	}

	// Scrape concurrently: a dozen sequential 4-second timeouts would outrun
	// the collection interval exactly when it matters, when the exporters are
	// unreachable.
	results := make([][]promSample, len(targets))
	errs := make([]error, len(targets))
	sem := make(chan struct{}, cnpgScrapeConcurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], errs[i] = c.scrapeExporter(ctx, t.ip, t.port, t.want)
		}(i, t)
	}
	wg.Wait()

	// Fold the readings back in. Pooler samples accumulate per pooler across
	// its replicas; instance samples land on their one instance.
	poolerSamples := map[string][]promSample{}
	primarySamples := map[int][]promSample{}
	for i, t := range targets {
		if errs[i] != nil {
			c.logger.Debug("kubernetes: cnpg exporter unreachable",
				"ip", t.ip, "port", t.port, "error", errs[i],
				"hint", "a NetworkPolicy may be blocking the agent from the pod network")
			continue
		}
		if t.poolerKey != "" {
			poolerSamples[t.poolerKey] = append(poolerSamples[t.poolerKey], results[i]...)
			continue
		}
		cs := &out.Postgres[t.clusterIdx]
		for j := range cs.Instances {
			if cs.Instances[j].Name != t.instance {
				continue
			}
			applyInstanceSamples(&cs.Instances[j], results[i])
			if cs.Instances[j].Role == "primary" {
				primarySamples[t.clusterIdx] = results[i]
			}
		}
	}

	for i := range out.Postgres {
		cs := &out.Postgres[i]
		for j := range cs.Poolers {
			key := cs.Poolers[j].Namespace + "/" + cs.Poolers[j].Name
			if s, ok := poolerSamples[key]; ok {
				applyPoolerSamples(&cs.Poolers[j], s)
			}
		}
		// Databases are read from the primary only. A replica reports the same
		// sizes but its own (replayed) transaction counters, so summing across
		// instances would double-count writes.
		if s, ok := primarySamples[i]; ok {
			cs.Databases = c.databaseStates(cs.Namespace+"/"+cs.Name, s, now)
			cs.sizeMeasured = true
		}
		for _, d := range cs.Databases {
			cs.TotalSizeBytes += d.SizeBytes
			if d.TransactionsPerSecond != nil {
				v := *d.TransactionsPerSecond
				if cs.TransactionsSec == nil {
					cs.TransactionsSec = new(float64)
				}
				*cs.TransactionsSec += v
			}
		}
		for _, inst := range cs.Instances {
			if inst.Role == "primary" || inst.LagSeconds == nil {
				continue
			}
			if cs.MaxLagSeconds == nil || *inst.LagSeconds > *cs.MaxLagSeconds {
				v := *inst.LagSeconds
				cs.MaxLagSeconds = &v
			}
		}
	}

	c.pruneCNPGCounters(out, primarySamples)
	return out
}

// pruneCNPGCounters drops rate baselines nobody will read again: those of a
// cluster that has disappeared or become excluded, and those of a database its
// primary stopped reporting. Without pruning, the map grows by one entry per
// database ever seen. A cluster whose primary was not scraped this cycle keeps
// its baselines, so a single missed scrape does not cost the next rate.
func (c *Collector) pruneCNPGCounters(r cnpgReport, scraped map[int][]promSample) {
	live := map[string]bool{}
	measured := map[string]map[string]bool{}
	for i, cs := range r.Postgres {
		key := cs.Namespace + "/" + cs.Name
		live[key] = true
		if _, ok := scraped[i]; ok {
			dbs := map[string]bool{}
			for _, d := range cs.Databases {
				dbs[d.Name] = true
			}
			measured[key] = dbs
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.cnpgLast {
		// Keys are "<namespace>/<cluster>|<database>"; the cluster half cannot
		// contain '|', the database name can.
		cluster, db, _ := strings.Cut(k, "|")
		if !live[cluster] {
			delete(c.cnpgLast, k)
			continue
		}
		if dbs, ok := measured[cluster]; ok && !dbs[db] {
			delete(c.cnpgLast, k)
		}
	}
}

// applyInstanceSamples maps one instance exporter's readings onto its state.
func applyInstanceSamples(inst *cnpgInstanceState, samples []promSample) {
	set := func(dst **float64, v float64) {
		x := v
		*dst = &x
	}
	for _, s := range samples {
		switch s.Name {
		case "cnpg_pg_settings_setting":
			if s.Labels["name"] == "max_connections" {
				set(&inst.MaxConnections, s.Value)
			}
		case "cnpg_collector_up":
			set(&inst.PostgresUp, s.Value)
		case "cnpg_collector_postgres_version":
			// The value is 1; the version rides in a label.
			if v := s.Labels["full"]; v != "" {
				inst.PostgresVersion = v
			}
		case "cnpg_pg_replication_lag":
			set(&inst.LagSeconds, s.Value)
		case "cnpg_pg_replication_in_recovery":
			inst.InRecovery = s.Value == 1
		case "cnpg_pg_replication_streaming_replicas":
			set(&inst.StreamingReplicas, s.Value)
		case "cnpg_pg_replication_slots_active":
			if inst.SlotsActive == nil {
				set(&inst.SlotsActive, 0)
			}
			*inst.SlotsActive += s.Value
		case "cnpg_backends_total":
			if inst.Backends == nil {
				set(&inst.Backends, 0)
			}
			*inst.Backends += s.Value
		case "cnpg_backends_max_tx_duration_seconds":
			// One series per (datname, usename); the cluster-wide answer is the
			// longest of them, not their sum.
			if inst.LongestTxSeconds == nil || s.Value > *inst.LongestTxSeconds {
				set(&inst.LongestTxSeconds, s.Value)
			}
		}
	}
	// HTTP reachability and database health are separate signals.
	if len(samples) > 0 {
		inst.Reachable = true
	}
}

// databaseStates turns the primary's per-database counters into sizes and
// rates, using the previous poll as the baseline.
func (c *Collector) databaseStates(clusterKey string, samples []promSample, now time.Time) []cnpgDatabaseState {
	type raw struct {
		size      float64
		commits   float64
		rollbacks float64
		tupReturn float64
		blksHit   float64
		blksRead  float64
		deadlocks float64
		backends  float64
		seen      bool
	}
	byDB := map[string]*raw{}
	get := func(name string) *raw {
		if byDB[name] == nil {
			byDB[name] = &raw{}
		}
		return byDB[name]
	}

	for _, s := range samples {
		db := s.Labels["datname"]
		// The exporter emits a datname="" row for cluster-wide totals, and
		// template0/template1 are not databases anyone runs queries against.
		if db == "" || db == "template0" || db == "template1" {
			continue
		}
		switch s.Name {
		case "cnpg_pg_database_size_bytes":
			r := get(db)
			r.size, r.seen = s.Value, true
		case "cnpg_pg_stat_database_xact_commit":
			get(db).commits = s.Value
		case "cnpg_pg_stat_database_xact_rollback":
			get(db).rollbacks = s.Value
		case "cnpg_pg_stat_database_tup_returned":
			get(db).tupReturn = s.Value
		case "cnpg_pg_stat_database_blks_hit":
			get(db).blksHit = s.Value
		case "cnpg_pg_stat_database_blks_read":
			get(db).blksRead = s.Value
		case "cnpg_pg_stat_database_deadlocks":
			get(db).deadlocks = s.Value
		case "cnpg_backends_total":
			// The exporter has no pg_stat_database_numbackends series; the
			// per-database connection count is this one, which is emitted per
			// (application_name, datname, state, usename) and has to be summed.
			get(db).backends += s.Value
		}
	}

	// The exporter's own snapshot time. An exporter that does not publish it
	// falls back to the poll time, which is coarser but still correct.
	sampledAt := now
	for _, s := range samples {
		if s.Name == "cnpg_last_update_timestamp" && s.Value > 0 {
			sampledAt = time.Unix(int64(s.Value), 0)
			break
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cnpgLast == nil {
		c.cnpgLast = map[string]cnpgCounters{}
	}

	out := make([]cnpgDatabaseState, 0, len(byDB))
	for name, r := range byDB {
		if !r.seen {
			// No size row means the database was only mentioned by a stat
			// series (e.g. one that survived a DROP DATABASE in the stats
			// collector). Not a database worth listing.
			continue
		}
		st := cnpgDatabaseState{
			Name:      name,
			SizeBytes: r.size,
			Deadlocks: r.deadlocks,
			Backends:  r.backends,
		}

		key := clusterKey + "|" + name
		cur := cnpgCounters{
			when: sampledAt, commits: r.commits, rollbacks: r.rollbacks,
			tupReturn: r.tupReturn, blksHit: r.blksHit, blksRead: r.blksRead,
		}
		if prev, ok := c.cnpgLast[key]; ok {
			// Zero when both polls read the same cached snapshot. Every rate is
			// then left absent rather than reported as zero.
			secs := sampledAt.Sub(prev.when).Seconds()
			// A counter that went backwards means Postgres restarted or
			// pg_stat_reset ran. Publishing (small - large)/dt would emit a
			// large negative rate, so the sample is dropped and the new
			// baseline is kept for next time.
			if secs > 0 && r.commits >= prev.commits && r.rollbacks >= prev.rollbacks {
				st.TransactionsPerSecond = ptrFloat((r.commits - prev.commits + r.rollbacks - prev.rollbacks) / secs)
				st.RollbacksPerSecond = ptrFloat((r.rollbacks - prev.rollbacks) / secs)
			}
			if secs > 0 && r.tupReturn >= prev.tupReturn {
				st.TuplesReadPerSecond = ptrFloat((r.tupReturn - prev.tupReturn) / secs)
			}
			// Cache hit ratio over the interval, not over the database's
			// lifetime: a lifetime ratio is dominated by history and barely
			// moves when the working set stops fitting in memory.
			hit, read := r.blksHit-prev.blksHit, r.blksRead-prev.blksRead
			if hit >= 0 && read >= 0 && hit+read > 0 {
				st.CacheHitRatio = ptrFloat(hit / (hit + read) * 100)
			}
		}
		c.cnpgLast[key] = cur

		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// applyPoolerSamples sums one pooler's replicas into a single row.
//
// pgbouncer publishes its stats per database and already as per-second
// averages, so the rates add straight up. The timings do not: a plain mean
// across databases lets one idle database with a single slow query dominate
// the number, so each database's timing is weighted by its share of the query
// rate.
func applyPoolerSamples(ps *cnpgPoolerState, samples []promSample) {
	if len(samples) == 0 {
		return
	}
	ps.Reachable = true

	rate := map[string]float64{}
	var qps float64
	var sawStats bool

	for _, s := range samples {
		switch s.Name {
		case "cnpg_pgbouncer_stats_avg_query_count":
			rate[s.Labels["database"]] += s.Value
			qps += s.Value
			sawStats = true
		case "cnpg_pgbouncer_pools_cl_active":
			ps.ClientsActive += s.Value
		case "cnpg_pgbouncer_pools_cl_waiting":
			ps.ClientsWaiting += s.Value
		case "cnpg_pgbouncer_pools_sv_active":
			ps.ServersActive += s.Value
		case "cnpg_pgbouncer_pools_sv_idle":
			ps.ServersIdle += s.Value
		case "cnpg_pgbouncer_pools_maxwait":
			if s.Value > ps.MaxWaitSeconds {
				ps.MaxWaitSeconds = s.Value
			}
		case "cnpg_pgbouncer_pools_pool_mode":
			// pgbouncer's own admin database is always session-pooled and says
			// nothing about how application traffic is pooled.
			if ps.PoolMode == "" && s.Labels["database"] != "pgbouncer" {
				if m, ok := cnpgPoolModes[s.Value]; ok {
					ps.PoolMode = m
				}
			}
		}
	}
	if !sawStats {
		return
	}
	ps.QueriesPerSecond = ptrFloat(qps)

	// µs in pgbouncer, ms in the report.
	weighted := func(name string) *float64 {
		var num, den float64
		for _, s := range samples {
			if s.Name != name {
				continue
			}
			w := rate[s.Labels["database"]]
			num += s.Value * w
			den += w
		}
		if den == 0 {
			return nil
		}
		return ptrFloat(num / den / 1000)
	}
	ps.AvgQueryTimeMs = weighted("cnpg_pgbouncer_stats_avg_query_time")
	ps.AvgWaitTimeMs = weighted("cnpg_pgbouncer_stats_avg_wait_time")
}

func ptrFloat(v float64) *float64 { return &v }

// cnpgCounts is the cluster-wide roll-up emitted as plain gauges.
type cnpgCounts struct {
	clusters    int
	healthy     int
	instances   int
	ready       int
	unreachable int
	poolers     int
}

func countCNPG(r cnpgReport) cnpgCounts {
	var c cnpgCounts
	for _, cl := range r.Postgres {
		c.clusters++
		if cl.Healthy {
			c.healthy++
		}
		c.instances += cl.InstancesTotal
		c.ready += cl.InstancesReady
		for _, i := range cl.Instances {
			if i.Scraped && !i.Reachable {
				c.unreachable++
			}
		}
		c.poolers += len(cl.Poolers)
	}
	return c
}

// cnpgLabels builds the label set shared by every per-cluster series. Namespace
// is included because two teams can each run a cluster called "postgres".
func cnpgLabels(cl cnpgClusterState, extra ...string) map[string]string {
	l := map[string]string{"namespace": cl.Namespace, "pg_cluster": cl.Name}
	for i := 0; i+1 < len(extra); i += 2 {
		l[extra[i]] = extra[i+1]
	}
	return l
}
