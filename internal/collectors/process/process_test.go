package process

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/config"
)

func TestCPUPercent(t *testing.T) {
	c := NewCollector(config.ProcessConfig{EnableProcessMonitoring: true}, "host", "key", "http://127.0.0.1:1")
	t0 := time.Now()

	// First observation of a PID has nothing to compare against.
	if _, ok := c.cpuPercent("nginx", &ProcessStats{PID: 10, CPUTime: 5 * time.Second}, t0); ok {
		t.Fatal("first observation must not report a percentage")
	}

	// 500 ms of CPU over a 10 s interval is 5% of one core.
	got, ok := c.cpuPercent("nginx", &ProcessStats{PID: 10, CPUTime: 5500 * time.Millisecond}, t0.Add(10*time.Second))
	if !ok || got < 4.99 || got > 5.01 {
		t.Fatalf("cpuPercent = %v, %v; want 5, true", got, ok)
	}

	// A different PID under the same name is a restarted process: its
	// counter started from zero, so the previous sample is meaningless.
	if _, ok := c.cpuPercent("nginx", &ProcessStats{PID: 11, CPUTime: time.Second}, t0.Add(20*time.Second)); ok {
		t.Fatal("PID change must reset the baseline")
	}

	// forget() drops the baseline entirely.
	c.forget("nginx")
	if _, ok := c.cpuPercent("nginx", &ProcessStats{PID: 11, CPUTime: 2 * time.Second}, t0.Add(30*time.Second)); ok {
		t.Fatal("forgotten process must start over")
	}
}

func TestMetricSuffix(t *testing.T) {
	if got := metricSuffix("My App Server"); got != "my_app_server" {
		t.Errorf("metricSuffix = %q", got)
	}
}

// A process whose CPU time could not be read must not leave a zero baseline
// behind: the next good read would then be its whole lifetime's CPU over one
// interval.
func TestCollect_UnknownCPUTimeIsNotABaseline(t *testing.T) {
	c := NewCollector(config.ProcessConfig{EnableProcessMonitoring: true}, "host", "key", "http://127.0.0.1:1")
	t0 := time.Now()
	c.observe("nginx", &ProcessStats{PID: 10, CPUTime: 100 * time.Second, CPUKnown: true}, t0)
	if _, ok := c.observe("nginx", &ProcessStats{PID: 10}, t0.Add(10*time.Second)); ok {
		t.Fatal("unknown CPU time produced a percentage")
	}
	if _, ok := c.observe("nginx", &ProcessStats{PID: 10, CPUTime: 3600 * time.Second, CPUKnown: true}, t0.Add(20*time.Second)); ok {
		t.Fatal("a failed read left a baseline behind")
	}
}

// Unknown memory is not reported as 0 MB.
func TestProcessMetrics_OmitsUnknownMemory(t *testing.T) {
	c := NewCollector(config.ProcessConfig{EnableProcessMonitoring: true}, "host", "key", "http://127.0.0.1:1")
	out := c.processMetrics(ProcessToMonitor{ProcessName: "nginx", Enabled: true}, &ProcessStats{PID: 10}, time.Now())
	for _, m := range out {
		if m.Name == "process_memory_mb_nginx" {
			t.Errorf("memory emitted as %v without a reading", m.Value)
		}
	}
	if len(out) == 0 || out[0].Name != "process_up_nginx" || out[0].Value != 1 {
		t.Errorf("process_up missing: %+v", out)
	}
}

// A failed config fetch is retried after a short delay, not on every cycle,
// and not only after the full refresh interval.
func TestProcessList_FailedFetchBacksOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := NewCollector(config.ProcessConfig{EnableProcessMonitoring: true, ConfigFetchInterval: 5 * time.Minute}, "host", "key", srv.URL)
	for i := 0; i < 3; i++ {
		c.processList(context.Background())
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("fetched %d times in one retry window, want 1", n)
	}
	c.mu.Lock()
	wait := time.Until(c.nextFetch)
	c.mu.Unlock()
	if wait <= 0 || wait > fetchRetryDelay {
		t.Fatalf("next fetch in %v, want within %v", wait, fetchRetryDelay)
	}
}
