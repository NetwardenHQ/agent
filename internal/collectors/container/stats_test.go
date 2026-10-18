package container

import (
	"testing"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

func has(ms []metrics.Metric, name string) (float64, bool) {
	for _, m := range ms {
		if m.Name == name {
			return m.Value, true
		}
	}
	return 0, false
}

// The socket path must use the same CPU scale as `podman stats` / `docker
// stats`: 100 = one core. 2 s of container CPU over a 2 s window on a 4-CPU
// host (8 s of host CPU time) is one core fully busy.
func TestConvertAPIStats_CPUIsPercentOfOneCore(t *testing.T) {
	var s statsFromAPI
	s.CPUStats.CPUUsage.TotalUsage = 3e9
	s.PreCPUStats.CPUUsage.TotalUsage = 1e9
	s.CPUStats.SystemUsage = 18e9
	s.PreCPUStats.SystemUsage = 10e9
	s.CPUStats.OnlineCPUs = 4
	got := convertAPIStats("c", &s)
	if !got.CPUKnown || got.CPUPercent < 99.99 || got.CPUPercent > 100.01 {
		t.Errorf("CPUPercent = %v (known %v), want 100", got.CPUPercent, got.CPUKnown)
	}
}

// Without a previous sample (or a CPU count) there is no utilization.
func TestConvertAPIStats_NoPreviousSampleIsUnknown(t *testing.T) {
	var s statsFromAPI
	s.CPUStats.CPUUsage.TotalUsage = 3e9
	s.CPUStats.SystemUsage = 18e9
	s.CPUStats.OnlineCPUs = 4
	if got := convertAPIStats("c", &s); got.CPUKnown {
		t.Errorf("CPU known without a previous sample: %v", got.CPUPercent)
	}
}

// Unknown figures are omitted rather than sent as 0, notably the memory
// limit, which the podman CLI never reports.
func TestStatsMetrics_OmitsUnknown(t *testing.T) {
	c := &Collector{builder: metrics.NewBuilder().WithHostname("h")}
	out := c.statsMetrics(&ContainerStats{ContainerID: "c"}, map[string]string{})
	for _, name := range []string{
		"container_cpu_usage_percent", "container_memory_usage_bytes",
		"container_memory_limit_bytes", "container_memory_usage_percent",
		"container_network_rx_bytes", "container_disk_read_bytes",
	} {
		if v, ok := has(out, name); ok {
			t.Errorf("%s = %v emitted for an unknown figure", name, v)
		}
	}
}
