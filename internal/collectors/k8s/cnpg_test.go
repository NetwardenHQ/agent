package k8s

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// instanceMetrics is a trimmed exporter body captured from a CloudNativePG 1.30
// instance.
const instanceMetrics = `
# HELP cnpg_collector_up 1 if the collector is up
# TYPE cnpg_collector_up gauge
cnpg_collector_up{cluster="postgres"} 1
cnpg_collector_postgres_version{cluster="postgres",full="18.6"} 18.6
cnpg_pg_replication_lag 0
cnpg_pg_replication_in_recovery 0
cnpg_pg_replication_streaming_replicas 2
cnpg_pg_replication_slots_active{slot_name="postgres_1"} 1
cnpg_pg_replication_slots_active{slot_name="postgres_3"} 1
cnpg_backends_total{application_name="",datname="appdb",state="idle",usename="app_user"} 12
cnpg_backends_total{application_name="TimescaleDB Background Worker Scheduler",datname="appdb",state="idle",usename="postgres"} 1
cnpg_backends_max_tx_duration_seconds{application_name="x",datname="appdb",usename="a"} 3
cnpg_backends_max_tx_duration_seconds{application_name="y",datname="analytics",usename="b"} 11
cnpg_pg_database_size_bytes{datname="appdb"} 1.158682303e+09
cnpg_pg_database_size_bytes{datname="template1"} 8.132287e+06
cnpg_pg_stat_database_xact_commit{datname="appdb"} 1000
cnpg_pg_stat_database_xact_commit{datname=""} 99
cnpg_pg_stat_database_xact_rollback{datname="appdb"} 100
cnpg_pg_stat_database_tup_returned{datname="appdb"} 5000
cnpg_pg_stat_database_blks_hit{datname="appdb"} 900
cnpg_pg_stat_database_blks_read{datname="appdb"} 100
cnpg_pg_stat_database_deadlocks{datname="appdb"} 2
cnpg_pg_stat_database_numbackends{datname="appdb"} 13
`

const poolerMetrics = `
cnpg_pgbouncer_stats_avg_query_count{database="busy"} 100
cnpg_pgbouncer_stats_avg_query_count{database="idle"} 0
cnpg_pgbouncer_stats_avg_query_time{database="busy"} 1000
cnpg_pgbouncer_stats_avg_query_time{database="idle"} 900000
cnpg_pgbouncer_stats_avg_wait_time{database="busy"} 2000
cnpg_pgbouncer_pools_cl_active{database="busy",user="u"} 5
cnpg_pgbouncer_pools_cl_waiting{database="busy",user="u"} 1
cnpg_pgbouncer_pools_sv_active{database="busy",user="u"} 3
cnpg_pgbouncer_pools_sv_idle{database="busy",user="u"} 7
cnpg_pgbouncer_pools_maxwait{database="busy",user="u"} 4
cnpg_pgbouncer_pools_pool_mode{database="pgbouncer",user="pgbouncer"} 3
cnpg_pgbouncer_pools_pool_mode{database="busy",user="u"} 2
`

func instanceSamples(t *testing.T) []promSample {
	t.Helper()
	return parseProm(instanceMetrics, cnpgWantedInstance)
}

func TestInstanceSamplesFoldIntoState(t *testing.T) {
	var inst cnpgInstanceState
	applyInstanceSamples(&inst, instanceSamples(t))

	if !inst.Reachable {
		t.Fatal("exporter answered but the instance is marked unreachable")
	}
	if inst.PostgresVersion != "18.6" {
		t.Fatalf("postgres version = %q, want 18.6 (it rides in the `full` label, not the value)", inst.PostgresVersion)
	}
	if inst.StreamingReplicas == nil || *inst.StreamingReplicas != 2 {
		t.Fatalf("streaming replicas = %v", inst.StreamingReplicas)
	}
	// Two slots, two backend rows: these are per-series and must be summed.
	if inst.SlotsActive == nil || *inst.SlotsActive != 2 {
		t.Fatalf("slots active = %v, want the sum of both slot series", inst.SlotsActive)
	}
	if inst.Backends == nil || *inst.Backends != 13 {
		t.Fatalf("backends = %v, want 12+1", inst.Backends)
	}
	// The longest transaction is the max across (datname, usename), not the sum.
	if inst.LongestTxSeconds == nil || *inst.LongestTxSeconds != 11 {
		t.Fatalf("longest tx = %v, want 11 (max, not sum)", inst.LongestTxSeconds)
	}
	if inst.InRecovery {
		t.Fatal("in_recovery is 0 on the primary")
	}
}

// An exporter that answers but whose own collector reports a failed Postgres
// scrape is still reachable.
func TestReachabilityIsAboutTheExporterNotTheDatabase(t *testing.T) {
	var inst cnpgInstanceState
	applyInstanceSamples(&inst, parseProm("cnpg_collector_up{cluster=\"x\"} 0\n", cnpgWantedInstance))
	if !inst.Reachable {
		t.Fatal("collector_up=0 must not mark the exporter unreachable")
	}
}

func TestNoSamplesLeavesEverythingUnset(t *testing.T) {
	var inst cnpgInstanceState
	applyInstanceSamples(&inst, nil)
	if inst.Reachable || inst.LagSeconds != nil || inst.Backends != nil {
		t.Fatal("an unreachable exporter must leave readings absent, not zeroed")
	}
}

func TestDatabaseRatesNeedTwoPolls(t *testing.T) {
	c := NewCollector("prod-cluster")
	now := time.Unix(1_700_000_000, 0)

	first := c.databaseStates("data/postgres", instanceSamples(t), now)
	if len(first) != 1 {
		t.Fatalf("got %d databases, want 1 (template1 and datname=\"\" are not databases)", len(first))
	}
	db := first[0]
	if db.Name != "appdb" {
		t.Fatalf("database = %q", db.Name)
	}
	if db.SizeBytes != 1158682303 {
		t.Fatalf("size = %v", db.SizeBytes)
	}
	// The first poll has no baseline, so rates are absent rather than zero.
	if db.TransactionsPerSecond != nil || db.CacheHitRatio != nil {
		t.Fatalf("first poll invented a rate: tps=%v hit=%v", db.TransactionsPerSecond, db.CacheHitRatio)
	}
	if db.Deadlocks != 2 || db.Backends != 13 {
		t.Fatalf("deadlocks=%v backends=%v", db.Deadlocks, db.Backends)
	}

	// Second poll, 10s later: +200 commits, +100 rollbacks, +900 hit, +100 read.
	advanced := strings.NewReplacer(
		"cnpg_pg_stat_database_xact_commit{datname=\"appdb\"} 1000",
		"cnpg_pg_stat_database_xact_commit{datname=\"appdb\"} 1200",
		"cnpg_pg_stat_database_xact_rollback{datname=\"appdb\"} 100",
		"cnpg_pg_stat_database_xact_rollback{datname=\"appdb\"} 200",
		"cnpg_pg_stat_database_blks_hit{datname=\"appdb\"} 900",
		"cnpg_pg_stat_database_blks_hit{datname=\"appdb\"} 1800",
		"cnpg_pg_stat_database_blks_read{datname=\"appdb\"} 100",
		"cnpg_pg_stat_database_blks_read{datname=\"appdb\"} 200",
	).Replace(instanceMetrics)

	second := c.databaseStates("data/postgres",
		parseProm(advanced, cnpgWantedInstance), now.Add(10*time.Second))
	db = second[0]
	if db.TransactionsPerSecond == nil || *db.TransactionsPerSecond != 30 {
		t.Fatalf("tps = %v, want (200+100)/10", db.TransactionsPerSecond)
	}
	if db.RollbacksPerSecond == nil || *db.RollbacksPerSecond != 10 {
		t.Fatalf("rollbacks/s = %v", db.RollbacksPerSecond)
	}
	// 900 hits against 100 reads over the interval, not the lifetime ratio.
	if db.CacheHitRatio == nil || *db.CacheHitRatio != 90 {
		t.Fatalf("cache hit = %v, want 90 (interval, not lifetime)", db.CacheHitRatio)
	}
}

// pg_stat_reset or a Postgres restart sends the counters backwards.
func TestCounterResetDropsTheSampleInsteadOfGoingNegative(t *testing.T) {
	c := NewCollector("prod-cluster")
	now := time.Unix(1_700_000_000, 0)
	c.databaseStates("data/postgres", instanceSamples(t), now)

	reset := strings.NewReplacer(
		"cnpg_pg_stat_database_xact_commit{datname=\"appdb\"} 1000",
		"cnpg_pg_stat_database_xact_commit{datname=\"appdb\"} 5",
	).Replace(instanceMetrics)

	got := c.databaseStates("data/postgres",
		parseProm(reset, cnpgWantedInstance), now.Add(10*time.Second))
	if got[0].TransactionsPerSecond != nil {
		t.Fatalf("emitted %v after a counter reset", *got[0].TransactionsPerSecond)
	}

	// The new baseline is kept, so the next poll produces a rate.
	forward := strings.NewReplacer(
		"cnpg_pg_stat_database_xact_commit{datname=\"appdb\"} 1000",
		"cnpg_pg_stat_database_xact_commit{datname=\"appdb\"} 105",
		"cnpg_pg_stat_database_xact_rollback{datname=\"appdb\"} 100",
		"cnpg_pg_stat_database_xact_rollback{datname=\"appdb\"} 100",
	).Replace(instanceMetrics)
	got = c.databaseStates("data/postgres",
		parseProm(forward, cnpgWantedInstance), now.Add(20*time.Second))
	if got[0].TransactionsPerSecond == nil || *got[0].TransactionsPerSecond != 10 {
		t.Fatalf("tps after recovery = %v, want (105-5)/10", got[0].TransactionsPerSecond)
	}
}

func TestPoolerSamplesFoldIntoState(t *testing.T) {
	ps := cnpgPoolerState{Name: "postgres-pooler"}
	applyPoolerSamples(&ps, parseProm(poolerMetrics, cnpgWantedPooler))

	if !ps.Reachable {
		t.Fatal("pooler marked unreachable despite samples")
	}
	if ps.QueriesPerSecond == nil || *ps.QueriesPerSecond != 100 {
		t.Fatalf("qps = %v", ps.QueriesPerSecond)
	}
	// The idle database reports a 900ms average over zero queries; an unweighted
	// mean would report ~450ms.
	if ps.AvgQueryTimeMs == nil || *ps.AvgQueryTimeMs != 1 {
		t.Fatalf("avg query time = %v ms, want 1 (weighted by query rate)", ps.AvgQueryTimeMs)
	}
	if ps.AvgWaitTimeMs == nil || *ps.AvgWaitTimeMs != 2 {
		t.Fatalf("avg wait = %v ms", ps.AvgWaitTimeMs)
	}
	if ps.ClientsActive != 5 || ps.ClientsWaiting != 1 || ps.ServersActive != 3 || ps.ServersIdle != 7 {
		t.Fatalf("pool counters wrong: %+v", ps)
	}
	if ps.MaxWaitSeconds != 4 {
		t.Fatalf("maxwait = %v", ps.MaxWaitSeconds)
	}
	// pgbouncer's own admin database is always session-pooled and is ignored.
	if ps.PoolMode != "transaction" {
		t.Fatalf("pool mode = %q, want transaction", ps.PoolMode)
	}
}

func TestPoolerWithNoTrafficReportsNoTimings(t *testing.T) {
	ps := cnpgPoolerState{}
	applyPoolerSamples(&ps, parseProm(
		"cnpg_pgbouncer_pools_cl_active{database=\"a\",user=\"u\"} 2\n", cnpgWantedPooler))
	if !ps.Reachable {
		t.Fatal("samples arrived; pooler is reachable")
	}
	if ps.QueriesPerSecond != nil || ps.AvgQueryTimeMs != nil {
		t.Fatal("invented a timing with no stats series present")
	}
}

func TestCountCNPGRollsUp(t *testing.T) {
	r := cnpgReport{Postgres: []cnpgClusterState{
		{Healthy: true, InstancesTotal: 3, InstancesReady: 3,
			Instances: []cnpgInstanceState{
				{Scraped: true, Reachable: true}, {Scraped: true, Reachable: true}, {Scraped: true, Reachable: false}},
			Poolers: []cnpgPoolerState{{}, {}}},
		// Never scraped (past cnpgMaxScrapes, or no pod IP): not unreachable.
		{Healthy: false, InstancesTotal: 2, InstancesReady: 1,
			Instances: []cnpgInstanceState{{}, {}}},
	}}
	c := countCNPG(r)
	if c.clusters != 2 || c.healthy != 1 || c.instances != 5 || c.ready != 4 ||
		c.unreachable != 1 || c.poolers != 2 {
		t.Fatalf("%+v", c)
	}
}

// A cluster without CloudNativePG emits no series: a gauge at zero would read as
// "all PostgreSQL clusters are unhealthy".
func TestNoSeriesWithoutCNPGClusters(t *testing.T) {
	c := NewCollector("prod-cluster")
	if got := c.emitCNPG(cnpgReport{}, time.Now()); len(got) != 0 {
		t.Fatalf("emitted %d series for a cluster running no CNPG", len(got))
	}
}

func TestEmitCNPGNamesTheClusterAndNamespace(t *testing.T) {
	c := NewCollector("prod-cluster")
	lag := 1.5
	got := c.emitCNPG(cnpgReport{Postgres: []cnpgClusterState{{
		Namespace: "data", Name: "postgres", Healthy: true,
		InstancesReady: 3, InstancesTotal: 3, MaxLagSeconds: &lag,
		Databases:    []cnpgDatabaseState{{Name: "appdb", SizeBytes: 10}},
		sizeMeasured: true,
		Poolers:      []cnpgPoolerState{{Name: "postgres-pooler", Scraped: true, Reachable: true, ClientsActive: 4}},
	}}}, time.Now())

	seen := map[string]bool{}
	for _, m := range got {
		seen[m.Name] = true
		// Two namespaces can each run a cluster called "postgres".
		if strings.HasPrefix(m.Name, "k8s_cnpg_cluster_") || strings.HasPrefix(m.Name, "k8s_cnpg_database_") {
			if m.Labels["namespace"] != "data" || m.Labels["pg_cluster"] != "postgres" {
				t.Fatalf("%s is missing its identity labels: %v", m.Name, m.Labels)
			}
		}
	}
	for _, want := range []string{
		"k8s_cnpg_clusters_total", "k8s_cnpg_cluster_healthy",
		"k8s_cnpg_replication_lag_seconds", "k8s_cnpg_database_size_bytes",
		"k8s_cnpg_pooler_clients_active",
	} {
		if !seen[want] {
			t.Errorf("missing series %s", want)
		}
	}
}

// The CloudNativePG exporter refreshes on its own ~40s cycle and serves cached
// values in between, so rates divide by the snapshot interval, not the poll gap.
func TestRatesUseTheExporterSnapshotTimeNotThePollTime(t *testing.T) {
	c := NewCollector("prod-cluster")
	body := func(stamp int, commits int) string {
		return "cnpg_last_update_timestamp " + itoa(stamp) + "\n" +
			"cnpg_pg_database_size_bytes{datname=\"app\"} 100\n" +
			"cnpg_pg_stat_database_xact_commit{datname=\"app\"} " + itoa(commits) + "\n" +
			"cnpg_pg_stat_database_xact_rollback{datname=\"app\"} 0\n"
	}
	parse := func(s string) []promSample {
		return parseProm(s, cnpgWantedInstance)
	}

	// Poll at wall-clock T. Exporter snapshot is from T-20.
	wall := time.Unix(1_789_000_000, 0)
	c.databaseStates("ns/pg", parse(body(1_789_000_000-20, 1000)), wall)

	// Poll 60s later. The exporter refreshed once in that window: its snapshot
	// is 40s newer, and 400 transactions happened in those 40 seconds.
	got := c.databaseStates("ns/pg", parse(body(1_789_000_000+20, 1400)), wall.Add(60*time.Second))
	if got[0].TransactionsPerSecond == nil {
		t.Fatal("no rate produced")
	}
	// 400/40 = 10. Dividing by the 60s poll gap would give 6.67.
	if *got[0].TransactionsPerSecond != 10 {
		t.Fatalf("tps = %v, want 10 (400 over the exporter's 40s, not the 60s poll gap)",
			*got[0].TransactionsPerSecond)
	}

	// A third poll on the same cached snapshot: no time has passed in the data,
	// so no rate is reported.
	got = c.databaseStates("ns/pg", parse(body(1_789_000_000+20, 1400)), wall.Add(90*time.Second))
	if got[0].TransactionsPerSecond != nil {
		t.Fatalf("reported %v from a repeated cached snapshot", *got[0].TransactionsPerSecond)
	}

	// A snapshot time that goes backwards (a restarted exporter, a stale cache
	// served after a fresh one) must not produce a negative rate.
	got = c.databaseStates("ns/pg", parse(body(1_789_000_000-100, 1400)), wall.Add(120*time.Second))
	if got[0].TransactionsPerSecond != nil {
		t.Fatalf("reported %v from a snapshot older than the baseline", *got[0].TransactionsPerSecond)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestDatabaseDownIsSeparateFromExporterReachability(t *testing.T) {
	var inst cnpgInstanceState
	applyInstanceSamples(&inst, parseProm("cnpg_collector_up 0\ncnpg_pg_settings_setting{name=\"max_connections\"} 300\n", cnpgWantedInstance))
	if !inst.Reachable || inst.PostgresUp == nil || *inst.PostgresUp != 0 {
		t.Fatalf("lost failure signal: %+v", inst)
	}
	c := NewCollector("test")
	report := cnpgReport{Postgres: []cnpgClusterState{{Instances: []cnpgInstanceState{inst}}}}
	for _, m := range c.emitCNPG(report, time.Now()) {
		if m.Name == "k8s_cnpg_instances_database_down" {
			if m.Value != 1 {
				t.Fatalf("got %v", m.Value)
			}
			return
		}
	}
	t.Fatal("missing database-down gauge")
}

func TestConnectionMaximumDoesNotAverageAwayBusyInstance(t *testing.T) {
	c := NewCollector("test")
	report := cnpgReport{Postgres: []cnpgClusterState{{Instances: []cnpgInstanceState{
		{Reachable: true, Backends: ptrFloat(270), MaxConnections: ptrFloat(300)},
		{Reachable: true, Backends: ptrFloat(3), MaxConnections: ptrFloat(300)},
	}}}}
	for _, m := range c.emitCNPG(report, time.Now()) {
		if m.Name == "k8s_cnpg_max_connections_percent" {
			if m.Value != 90 {
				t.Fatalf("got %v", m.Value)
			}
			return
		}
	}
	t.Fatal("missing maximum")
}

// Unmeasured CNPG readings are absent, not zero: an unreached pooler emits no
// client/server series, an unscraped primary emits no cluster size, and an
// instance skipped by the scrape ceiling is not counted as unreachable.
func TestEmitCNPGOmitsWhatWasNotMeasured(t *testing.T) {
	c := NewCollector("prod-cluster")
	got := c.emitCNPG(cnpgReport{Postgres: []cnpgClusterState{{
		Namespace: "data", Name: "postgres", InstancesReady: 1, InstancesTotal: 2,
		Instances: []cnpgInstanceState{{Name: "postgres-1"}, {Name: "postgres-2"}},
		Poolers: []cnpgPoolerState{
			{Name: "down", Scraped: true},
			{Name: "unplanned"},
		},
	}}}, time.Now())

	values := map[string]float64{}
	for _, m := range got {
		values[m.Name] = m.Value
		switch m.Name {
		case "k8s_cnpg_pooler_clients_active", "k8s_cnpg_pooler_clients_waiting",
			"k8s_cnpg_pooler_servers_active":
			t.Errorf("%s{pooler=%s} emitted for a pooler that was not reached", m.Name, m.Labels["pooler"])
		case "k8s_cnpg_cluster_size_bytes":
			t.Error("cluster size emitted although the primary was never scraped")
		}
	}
	if values["k8s_cnpg_instances_unreachable"] != 0 {
		t.Errorf("unscraped instances counted as unreachable: %v", values["k8s_cnpg_instances_unreachable"])
	}
	if values["k8s_cnpg_poolers_unreachable"] != 1 {
		t.Errorf("only the scraped-and-silent pooler is unreachable, got %v", values["k8s_cnpg_poolers_unreachable"])
	}
}

// Rate baselines of clusters and databases that are gone must not accumulate.
func TestCNPGBaselinesArePruned(t *testing.T) {
	c := NewCollector("prod-cluster")
	c.cnpgLast = map[string]cnpgCounters{
		"data/postgres|appdb":   {},
		"data/postgres|dropped": {},
		"data/old|appdb":        {},
		"data/unscraped|appdb":  {},
	}
	r := cnpgReport{Postgres: []cnpgClusterState{
		{Namespace: "data", Name: "postgres", Databases: []cnpgDatabaseState{{Name: "appdb"}}},
		{Namespace: "data", Name: "unscraped"},
	}}
	c.pruneCNPGCounters(r, map[int][]promSample{0: nil})
	for _, k := range []string{"data/postgres|appdb", "data/unscraped|appdb"} {
		if _, ok := c.cnpgLast[k]; !ok {
			t.Errorf("baseline %s should be kept", k)
		}
	}
	for _, k := range []string{"data/postgres|dropped", "data/old|appdb"} {
		if _, ok := c.cnpgLast[k]; ok {
			t.Errorf("baseline %s should be pruned", k)
		}
	}
}

// An exporter page is bounded, and a redirect is not followed: the agent
// scrapes the pod IP the API reported and nothing else.
func TestScrapeExporterIsBoundedAndDoesNotRedirect(t *testing.T) {
	var followed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/elsewhere":
			followed.Store(true)
			_, _ = io.WriteString(w, "cnpg_collector_up 1\n")
		default:
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	c := NewCollector("prod-cluster")
	if _, err := c.scrapeExporter(t.Context(), host, port, cnpgWantedInstance); err == nil {
		t.Fatal("a redirect must surface as a non-200, not be followed")
	}
	if followed.Load() {
		t.Fatal("the scraper followed a redirect")
	}

	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := strings.Repeat("x", 1023) + "\n"
		for written := 0; written <= maxExporterBytes; written += len(line) {
			if _, err := io.WriteString(w, line); err != nil {
				return
			}
		}
	}))
	defer big.Close()
	host, port = splitHostPort(t, big.URL)
	if _, err := c.scrapeExporter(t.Context(), host, port, cnpgWantedInstance); err == nil {
		t.Fatal("a page over maxExporterBytes must be an error")
	}
}

func splitHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), port
}
