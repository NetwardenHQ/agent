package metrics

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func newTestTracker(maxAge time.Duration) *DeltaTracker {
	return NewDeltaTracker(DeltaConfig{
		Threshold: 1.0,
		MaxAge:    maxAge,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func gauge(name string, value float64, labels map[string]string) Metric {
	return Metric{Name: name, Value: value, Type: MetricTypeGauge, Labels: labels, Timestamp: time.Now()}
}

func TestDeltaFirstSightingAndUnchangedValue(t *testing.T) {
	dt := newTestTracker(time.Hour)
	if !dt.ShouldSend(gauge("cpu_usage_percent", 40, nil)) {
		t.Fatal("a metric seen for the first time must be sent")
	}
	if dt.ShouldSend(gauge("cpu_usage_percent", 40, nil)) {
		t.Fatal("an unchanged value was sent again")
	}
	if dt.ShouldSend(gauge("cpu_usage_percent", 40.2, nil)) {
		t.Fatal("a change under the threshold was sent")
	}
	if !dt.ShouldSend(gauge("cpu_usage_percent", 41, nil)) {
		t.Fatal("a change over the threshold was not sent")
	}
}

// The comparison is against the value the server last received. Compared
// against the previous reading instead, a gauge that creeps by less than the
// threshold each cycle would never be sent, however far it has moved.
func TestDeltaSlowDriftIsMeasuredFromTheLastSentValue(t *testing.T) {
	dt := newTestTracker(time.Hour)
	dt.ShouldSend(gauge("disk_usage_percent", 50, nil))

	sent := 0
	value := 50.0
	for i := 0; i < 40; i++ {
		value += 0.2 // 0.4% of the value per reading
		if dt.ShouldSend(gauge("disk_usage_percent", value, nil)) {
			sent++
		}
	}
	// 50 -> 58 crosses a 1% step roughly every third reading.
	if sent < 10 {
		t.Fatalf("a gauge that moved from 50 to %.0f was sent %d times", value, sent)
	}
}

func TestDeltaZeroAndSeriesIdentity(t *testing.T) {
	dt := newTestTracker(time.Hour)
	dt.ShouldSend(gauge("k8s_cnpg_instances_unreachable", 0, nil))
	if !dt.ShouldSend(gauge("k8s_cnpg_instances_unreachable", 2, nil)) {
		t.Fatal("zero to non-zero was not sent")
	}
	if !dt.ShouldSend(gauge("k8s_cnpg_instances_unreachable", 0, nil)) {
		t.Fatal("back to zero was not sent")
	}

	// Each label set is its own series, whatever order the labels arrive in.
	a := map[string]string{"device": "sda", "mount": "/"}
	b := map[string]string{"mount": "/", "device": "sda"}
	other := map[string]string{"device": "sdb", "mount": "/data"}
	dt.ShouldSend(gauge("disk_usage_percent", 70, a))
	if dt.ShouldSend(gauge("disk_usage_percent", 70, b)) {
		t.Fatal("the same series with reordered labels was treated as new")
	}
	if !dt.ShouldSend(gauge("disk_usage_percent", 70, other)) {
		t.Fatal("a different series was suppressed")
	}
}

func TestDeltaCounterAndMaxAge(t *testing.T) {
	dt := newTestTracker(30 * time.Millisecond)
	counter := Metric{Name: "network_bytes_sent_total", Value: 1_000_000, Type: MetricTypeCounter}
	dt.ShouldSend(counter)
	counter.Value++
	if !dt.ShouldSend(counter) {
		t.Fatal("a counter that grew was not sent")
	}

	dt.ShouldSend(gauge("memory_usage_percent", 60, nil))
	if dt.ShouldSend(gauge("memory_usage_percent", 60, nil)) {
		t.Fatal("unchanged gauge sent inside the max age")
	}
	time.Sleep(40 * time.Millisecond)
	if !dt.ShouldSend(gauge("memory_usage_percent", 60, nil)) {
		t.Fatal("unchanged gauge not refreshed after the max age")
	}
}

// A batch the server never received must be offered again. Forget drops the
// tracker's memory of those series, so their next reading is sent in full.
func TestDeltaForgetResendsWhatWasNotDelivered(t *testing.T) {
	dt := newTestTracker(time.Hour)
	batch := []Metric{gauge("cpu_usage_percent", 40, nil), gauge("disk_usage_percent", 70, map[string]string{"mount": "/"})}
	if got := dt.FilterMetrics(batch); len(got) != 2 {
		t.Fatalf("first pass sent %d of 2", len(got))
	}
	if got := dt.FilterMetrics(batch); len(got) != 0 {
		t.Fatalf("unchanged batch sent %d", len(got))
	}

	dt.Forget(batch[:1])
	got := dt.FilterMetrics(batch)
	if len(got) != 1 || got[0].Name != "cpu_usage_percent" {
		t.Fatalf("after Forget, resent %v", got)
	}
}
