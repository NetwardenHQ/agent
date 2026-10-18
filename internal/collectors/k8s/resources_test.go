package k8s

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func nowForTest() time.Time { return time.Unix(1_700_000_000, 0) }

func pu(ns, name string, cpu, mem float64) podUsage {
	return podUsage{Namespace: ns, Name: name, resourceUsage: resourceUsage{CPUCores: cpu, MemBytes: mem}}
}

func TestTopPodsTakesTheUnionOfBothRankings(t *testing.T) {
	pods := []podUsage{
		pu("a", "cpu-hog", 4.0, 1),
		pu("a", "mem-hog", 0.01, 8e9), // idle on CPU, huge on memory
		pu("a", "quiet-1", 0.02, 2),
		pu("a", "quiet-2", 0.03, 3),
		pu("a", "quiet-3", 0.04, 4),
	}
	got := topPods(pods, 1)

	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	if !names["cpu-hog"] {
		t.Error("top-1 by CPU missing")
	}
	if !names["mem-hog"] {
		t.Error("top-1 by memory missing")
	}
	if len(got) != 2 {
		t.Fatalf("want the union (2), got %d", len(got))
	}
}

func TestTopPodsReturnsEverythingWhenUnderTheCap(t *testing.T) {
	pods := []podUsage{pu("a", "x", 1, 1), pu("a", "y", 2, 2)}
	if got := topPods(pods, 10); len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
}

func TestTopPodsIsDeterministic(t *testing.T) {
	pods := []podUsage{pu("b", "z", 1, 1), pu("a", "y", 2, 2), pu("a", "x", 3, 3)}
	first := topPods(pods, 2)
	second := topPods(pods, 2)
	for i := range first {
		if podKey(first[i]) != podKey(second[i]) {
			t.Fatal("ordering is unstable across calls; series would flap")
		}
	}
}

// Without metrics-server the usage series are absent rather than zero.
func TestEmitUsageIsSilentWithoutMetricsServer(t *testing.T) {
	c := NewCollector("prod-cluster")
	if got := c.emitUsage(usageSnapshot{Available: false}, nowForTest()); len(got) != 0 {
		t.Fatalf("emitted %d series with no metrics API; expected none", len(got))
	}
}

func TestEmitUsagePercentagesUseAllocatable(t *testing.T) {
	c := NewCollector("prod-cluster")
	u := usageSnapshot{
		Available:     true,
		TotalCPUCores: 1, AllocCPUCores: 4,
		TotalMemBytes: 2e9, AllocMemBytes: 8e9,
		ByNamespace: map[string]resourceUsage{},
	}
	got := c.emitUsage(u, nowForTest())

	find := func(name string) (float64, bool) {
		for _, m := range got {
			if m.Name == name {
				return m.Value, true
			}
		}
		return 0, false
	}
	if v, ok := find("k8s_cpu_usage_percent"); !ok || !almost(v, 25) {
		t.Errorf("cpu percent = %v (found=%v), want 25", v, ok)
	}
	if v, ok := find("k8s_memory_usage_percent"); !ok || !almost(v, 25) {
		t.Errorf("memory percent = %v (found=%v), want 25", v, ok)
	}
}

// A zero allocatable figure must not produce NaN or Inf percentages.
func TestEmitUsageSkipsPercentWhenAllocatableUnknown(t *testing.T) {
	c := NewCollector("prod-cluster")
	u := usageSnapshot{Available: true, TotalCPUCores: 1, ByNamespace: map[string]resourceUsage{}}
	for _, m := range c.emitUsage(u, nowForTest()) {
		if m.Name == "k8s_cpu_usage_percent" || m.Name == "k8s_memory_usage_percent" {
			t.Fatalf("emitted %s with no allocatable figure", m.Name)
		}
	}
}

func TestDatabaseMemoryIncludesQuietInstanceAndRejectsUnknownLimits(t *testing.T) {
	p := Pod{Metadata: ObjectMeta{Name: "db-1", Namespace: "data", Labels: map[string]string{"cnpg.io/podRole": "instance"}}}
	c := Container{Name: "postgres"}
	c.Resources.Limits = map[string]string{"memory": "4Gi"}
	p.Spec.Containers = []Container{c}
	result := databaseMemoryPercent([]podUsage{pu("data", "db-1", 0, 3*1024*1024*1024)}, []Pod{p})
	if result == nil || *result != 75 {
		t.Fatalf("got %v", result)
	}
	p.Spec.Containers[0].Resources.Limits = nil
	if got := databaseMemoryPercent([]podUsage{pu("data", "db-1", 0, 1)}, []Pod{p}); got != nil {
		t.Fatal("missing limit became a healthy value")
	}
}

func TestNodeMemoryMaximumDoesNotHideOneFullNode(t *testing.T) {
	c := NewCollector("test")
	usage := usageSnapshot{Available: true, Nodes: []nodeUsage{
		{AllocMemBytes: 100, resourceUsage: resourceUsage{MemBytes: 95}},
		{AllocMemBytes: 100, resourceUsage: resourceUsage{MemBytes: 10}},
	}}
	for _, m := range c.emitUsage(usage, nowForTest()) {
		if m.Name == "k8s_node_max_memory_percent" {
			if m.Value != 95 {
				t.Fatalf("got %v", m.Value)
			}
			return
		}
	}
	t.Fatal("missing node maximum")
}

// A node whose usage does not parse is excluded from the node list and the
// cluster totals.
func TestCollectUsageSkipsUnreadableNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case nodeMetricsPath:
			_, _ = io.WriteString(w, `{"items":[`+
				`{"metadata":{"name":"good"},"usage":{"cpu":"500m","memory":"1Gi"}},`+
				`{"metadata":{"name":"bad"},"usage":{"cpu":"garbage","memory":"1Gi"}}]}`)
		default:
			_, _ = io.WriteString(w, `{"items":[]}`)
		}
	}))
	defer srv.Close()
	c := NewCollector("prod-cluster")
	c.client = testClient(t, srv)

	nodes := []Node{
		{Metadata: ObjectMeta{Name: "good"}, Status: NodeStatus{Allocatable: map[string]string{"cpu": "1", "memory": "2Gi"}}},
		{Metadata: ObjectMeta{Name: "bad"}, Status: NodeStatus{Allocatable: map[string]string{"cpu": "1", "memory": "2Gi"}}},
	}
	u := c.collectUsage(t.Context(), nodes)
	if len(u.Nodes) != 1 || u.Nodes[0].Name != "good" {
		t.Fatalf("nodes = %+v; the unreadable node must be left out", u.Nodes)
	}
	if !almost(u.TotalCPUCores, 0.5) || !almost(u.AllocCPUCores, 1) {
		t.Fatalf("totals %v / %v must cover only the readable node", u.TotalCPUCores, u.AllocCPUCores)
	}
}
