package k8s

import (
	"context"
	"sort"
)

/*
Node and pod resource usage, read from metrics.k8s.io (metrics-server).

These are polled rather than watched: metrics.k8s.io is an aggregated API backed by an
in-memory store. It does not support watch, and its values are recomputed on a
short interval anyway, so a list per collection cycle is both the only option
and the right one.
*/

const (
	nodeMetricsPath = "/apis/metrics.k8s.io/v1beta1/nodes"
	podMetricsPath  = "/apis/metrics.k8s.io/v1beta1/pods"

	// How many individual pods get their own series.
	//
	// Per-pod is the highest-cardinality thing this collector could emit: pods
	// churn constantly, so every restarted pod would leave a dead series behind
	// forever. The per-NAMESPACE rollups below are the ones meant for alerting
	// and dashboards; this top-N answers "what is consuming the node", which only
	// concerns the handful at the top.
	topPodSeries = 10
)

type resourceUsage struct {
	CPUCores float64
	MemBytes float64
}

type nodeUsage struct {
	Name string
	resourceUsage
	// From the Node object, not metrics-server.
	AllocCPUCores float64
	AllocMemBytes float64
	StorageBytes  float64
}

type podUsage struct {
	Namespace string
	Name      string
	resourceUsage
}

// metricsNodeList and metricsPodList declare only the fields used.
type metricsNodeList struct {
	Items []struct {
		Metadata ObjectMeta        `json:"metadata"`
		Usage    map[string]string `json:"usage"`
	} `json:"items"`
}

type metricsPodList struct {
	Items []struct {
		Metadata   ObjectMeta `json:"metadata"`
		Containers []struct {
			Name  string            `json:"name"`
			Usage map[string]string `json:"usage"`
		} `json:"containers"`
	} `json:"items"`
}

// usageSnapshot is one poll of metrics.k8s.io, already aggregated.
type usageSnapshot struct {
	Storage               storageUsage
	Nodes                 []nodeUsage
	ByNamespace           map[string]resourceUsage
	TopPods               []podUsage
	AllPods               []podUsage
	DatabaseMemoryPercent *float64
	// Cluster rollups, summed from the node readings.
	TotalCPUCores, TotalMemBytes float64
	AllocCPUCores, AllocMemBytes float64
	Available                    bool
}

// collectUsage polls metrics.k8s.io and folds the readings against the node
// inventory already held by the reflectors.
//
// A failure here is not an error for the caller: metrics-server is
// an optional add-on, and a cluster without it must still report everything
// else. `Available` distinguishes "no metrics-server" from "zero usage".
func (c *Collector) collectUsage(ctx context.Context, nodes []Node) usageSnapshot {
	out := usageSnapshot{ByNamespace: map[string]resourceUsage{}}

	var nodeList metricsNodeList
	if err := c.client.List(ctx, nodeMetricsPath, &nodeList); err != nil {
		c.logger.Debug("kubernetes: node metrics unavailable",
			"path", nodeMetricsPath, "error", err,
			"hint", "metrics-server not installed, or the agent lacks metrics.k8s.io RBAC")
		return out
	}
	out.Available = true

	// Allocatable/capacity come from the Node objects the reflector already has.
	alloc := make(map[string]nodeUsage, len(nodes))
	for _, n := range nodes {
		nu := nodeUsage{Name: n.Metadata.Name}
		if v, ok := parseQuantity(n.Status.Allocatable["cpu"]); ok {
			nu.AllocCPUCores = v
		}
		if v, ok := parseQuantity(n.Status.Allocatable["memory"]); ok {
			nu.AllocMemBytes = v
		}
		// Capacity, not allocatable: disk pressure is about the filesystem.
		if v, ok := parseQuantity(n.Status.Capacity["ephemeral-storage"]); ok {
			nu.StorageBytes = v
		}
		alloc[n.Metadata.Name] = nu
	}

	for _, item := range nodeList.Items {
		nu := alloc[item.Metadata.Name]
		nu.Name = item.Metadata.Name
		cpu, cpuOK := parseQuantity(item.Usage["cpu"])
		mem, memOK := parseQuantity(item.Usage["memory"])
		if !cpuOK || !memOK {
			// An unreadable reading is no reading. Counting it as zero would
			// draw a node at 0% and drag the cluster totals down with it; its
			// allocatable is left out with it so the percentages stay honest.
			c.logger.Debug("kubernetes: unreadable node usage", "node", nu.Name,
				"cpu", item.Usage["cpu"], "memory", item.Usage["memory"])
			continue
		}
		nu.CPUCores, nu.MemBytes = cpu, mem
		out.Nodes = append(out.Nodes, nu)
		out.TotalCPUCores += nu.CPUCores
		out.TotalMemBytes += nu.MemBytes
		out.AllocCPUCores += nu.AllocCPUCores
		out.AllocMemBytes += nu.AllocMemBytes
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Name < out.Nodes[j].Name })

	var podList metricsPodList
	if err := c.client.List(ctx, podMetricsPath, &podList); err != nil {
		c.logger.Debug("kubernetes: pod metrics unavailable", "error", err)
		return out
	}

	pods := make([]podUsage, 0, len(podList.Items))
	for _, item := range podList.Items {
		ns := item.Metadata.Namespace
		if c.skip(ns) {
			continue
		}
		var p podUsage
		p.Namespace, p.Name = ns, item.Metadata.Name
		for _, ctr := range item.Containers {
			if v, ok := parseQuantity(ctr.Usage["cpu"]); ok {
				p.CPUCores += v
			}
			if v, ok := parseQuantity(ctr.Usage["memory"]); ok {
				p.MemBytes += v
			}
		}
		pods = append(pods, p)

		agg := out.ByNamespace[ns]
		agg.CPUCores += p.CPUCores
		agg.MemBytes += p.MemBytes
		out.ByNamespace[ns] = agg
	}

	out.AllPods = pods
	out.TopPods = topPods(pods, topPodSeries)
	return out
}

// topPods returns the union of the n hungriest by CPU and by memory. Union
// rather than one ranking: a pod pinning memory while idle on CPU is the one
// worth seeing, and a CPU-only ranking hides it.
func topPods(pods []podUsage, n int) []podUsage {
	if len(pods) <= n {
		sort.Slice(pods, func(i, j int) bool { return podKey(pods[i]) < podKey(pods[j]) })
		return pods
	}

	pick := map[string]podUsage{}

	byCPU := make([]podUsage, len(pods))
	copy(byCPU, pods)
	sort.Slice(byCPU, func(i, j int) bool { return byCPU[i].CPUCores > byCPU[j].CPUCores })
	for _, p := range byCPU[:n] {
		pick[podKey(p)] = p
	}

	byMem := make([]podUsage, len(pods))
	copy(byMem, pods)
	sort.Slice(byMem, func(i, j int) bool { return byMem[i].MemBytes > byMem[j].MemBytes })
	for _, p := range byMem[:n] {
		pick[podKey(p)] = p
	}

	out := make([]podUsage, 0, len(pick))
	for _, p := range pick {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return podKey(out[i]) < podKey(out[j]) })
	return out
}

func podKey(p podUsage) string { return p.Namespace + "/" + p.Name }

// databaseMemoryPercent returns the maximum working-set/limit ratio across
// CloudNativePG instance pods. Missing limits or
// missing measurements are unknown, never zero. Poolers are excluded.
func databaseMemoryPercent(usage []podUsage, pods []Pod) *float64 {
	limits := map[string]float64{}
	for _, p := range pods {
		if p.Metadata.Labels["cnpg.io/podRole"] != "instance" {
			continue
		}
		total, valid := 0.0, len(p.Spec.Containers) > 0
		for _, c := range p.Spec.Containers {
			amount, ok := parseQuantity(c.Resources.Limits["memory"])
			if !ok || amount <= 0 {
				valid = false
				break
			}
			total += amount
		}
		if valid {
			limits[p.Metadata.Namespace+"/"+p.Metadata.Name] = total
		}
	}
	var result *float64
	for _, p := range usage {
		if limit, ok := limits[podKey(p)]; ok {
			pct := p.MemBytes / limit * 100
			if result == nil || pct > *result {
				result = ptrFloat(pct)
			}
		}
	}
	return result
}
