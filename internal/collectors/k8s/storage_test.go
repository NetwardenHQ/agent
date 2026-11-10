package k8s

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStorageUsesAvailableSpaceAndWorstPVC(t *testing.T) {
	var s nodeSummary
	err := json.Unmarshal([]byte(`{"node":{"fs":{"capacityBytes":100,"availableBytes":60}},"pods":[{"volume":[{"capacityBytes":100,"availableBytes":1},{"pvcRef":{"name":"db"},"capacityBytes":100,"availableBytes":15},{"pvcRef":{"name":"other"},"capacityBytes":100,"availableBytes":90}]}]}`), &s)
	if err != nil {
		t.Fatal(err)
	}
	u := summarizeStorage(s)
	if u.NodePercent == nil || *u.NodePercent != 40 || u.PVCPercent == nil || *u.PVCPercent != 85 {
		t.Fatalf("wrong filesystem maxima: %+v", u)
	}
}
func TestStorageMissingReadingsAreNotZero(t *testing.T) {
	for _, s := range []filesystemStats{{}, {CapacityBytes: ptrFloat(0), AvailableBytes: ptrFloat(0)}, {CapacityBytes: ptrFloat(10), AvailableBytes: ptrFloat(11)}} {
		if filesystemUsedPercent(s) != nil {
			t.Fatal("missing/invalid reading became a healthy sample")
		}
	}
}

// volume feeds one data volume's free space into the forecast, a sample every
// fifteen minutes, and returns what the last sample made of it.
type forecastRun struct {
	history map[string][]storagePoint
	at      time.Time
}

func newForecastRun() *forecastRun {
	return &forecastRun{history: map[string][]storagePoint{}, at: time.Unix(1700000000, 0)}
}

func (f *forecastRun) sample(key string, capacity, available float64) (int, []storageRisk) {
	ready, risks := updateStorageForecast(f.history, map[string]filesystemStats{key: {CapacityBytes: ptrFloat(capacity), AvailableBytes: ptrFloat(available)}}, f.at)
	f.at = f.at.Add(15 * time.Minute)
	return ready, risks
}

// hours feeds `hours` of samples; free(i) is the free space at sample i.
func (f *forecastRun) hours(key string, capacity float64, hours int, free func(i int) float64) (ready int, risks []storageRisk) {
	for i := 0; i < hours*4; i++ {
		ready, risks = f.sample(key, capacity, free(i))
	}
	return
}

const gib = float64(1 << 30)

func TestStorageForecastNeedsADayOfHistory(t *testing.T) {
	f := newForecastRun()
	// Falling fast from the first sample: 30 GiB volume, 60% used, 0.1 GiB an hour.
	ready, risks := f.hours("pvc:prod/postgres-2", 30*gib, 23, func(i int) float64 { return 12*gib - float64(i)*0.025*gib })
	if ready != 0 || len(risks) != 0 {
		t.Fatalf("forecast on %d hours of history: ready=%d risks=%v", 23, ready, risks)
	}
}

func TestStorageForecastSteadyFillNamesTheVolume(t *testing.T) {
	f := newForecastRun()
	// 12 GiB free, falling 0.1 GiB an hour for two days: full in about three days.
	ready, risks := f.hours("pvc:prod/postgres-2", 30*gib, 48, func(i int) float64 { return 12*gib - float64(i)*0.025*gib })
	if ready != 1 || len(risks) != 1 {
		t.Fatalf("steady fill not forecast: ready=%d risks=%v", ready, risks)
	}
	r := risks[0]
	if r.Key != "pvc:prod/postgres-2" || r.Reason != riskFilling || r.Capacity != 30*gib {
		t.Fatalf("wrong risk: %+v", r)
	}
	if perHour := r.ChangePerHour / gib; perHour > -0.099 || perHour < -0.101 {
		t.Fatalf("rate %.4f GiB/h, want -0.1", perHour)
	}
	if r.HistoryHours < 47 || r.HistoryHours > 48 {
		t.Fatalf("history %.1f h, want about 48", r.HistoryHours)
	}
	if want := 12*gib - 191*0.025*gib; r.Available != want {
		t.Fatalf("available %.0f, want %.0f", r.Available, want)
	}
}

// One busy day must not predict a week: 173 MB of logs in a morning on a
// volume that had been flat is not a trend.
func TestStorageForecastOneBusyDayIsNotATrend(t *testing.T) {
	f := newForecastRun()
	_, risks := f.hours("pvc:prod/postgres-2", 30*gib, 36, func(int) float64 { return 14 * gib })
	if len(risks) != 0 {
		t.Fatal("flat volume at risk")
	}
	// Then twelve hours falling 0.2 GiB an hour. Extrapolated straight, full in under three days.
	_, risks = f.hours("pvc:prod/postgres-2", 30*gib, 12, func(i int) float64 { return 14*gib - float64(i)*0.05*gib })
	if len(risks) != 0 {
		t.Fatalf("a fall confined to the last hours was forecast as a trend: %+v", risks)
	}
}

func TestStorageForecastAFillThatStoppedIsNotATrend(t *testing.T) {
	f := newForecastRun()
	f.hours("pvc:a/b", 30*gib, 30, func(i int) float64 { return 14*gib - float64(i)*0.025*gib })
	_, risks := f.hours("pvc:a/b", 30*gib, 30, func(int) float64 { return 11 * gib })
	if len(risks) != 0 {
		t.Fatalf("a volume that stopped filling is still at risk: %+v", risks)
	}
}

func TestStorageForecastIgnoresSmallDropsAndRoomyVolumes(t *testing.T) {
	// Less than 1% of the volume lost over the window, however steadily.
	f := newForecastRun()
	if _, risks := f.hours("pvc:a/small", 1000*gib, 48, func(i int) float64 { return 400*gib - float64(i)*0.02*gib }); len(risks) != 0 {
		t.Fatalf("a drop under 1%% of the volume was forecast: %+v", risks)
	}
	// Under half full: there is time to see it coming.
	f = newForecastRun()
	if _, risks := f.hours("pvc:a/roomy", 30*gib, 48, func(i int) float64 { return 26*gib - float64(i)*0.05*gib }); len(risks) != 0 {
		t.Fatalf("a volume under half full was forecast: %+v", risks)
	}
	// Filling, but more than a week away.
	f = newForecastRun()
	if _, risks := f.hours("pvc:a/slow", 30*gib, 48, func(i int) float64 { return 12*gib - float64(i)*0.0025*gib }); len(risks) != 0 {
		t.Fatalf("a volume months from full was forecast: %+v", risks)
	}
}

// A sawtooth (WAL recycled, a table compressed) that still trends down is a
// fill; the regression sees through the teeth.
func TestStorageForecastSeesAFillThroughASawtooth(t *testing.T) {
	f := newForecastRun()
	_, risks := f.hours("pvc:prod/postgres-1", 30*gib, 60, func(i int) float64 {
		return 12*gib - float64(i)*0.025*gib + float64(i%16)*0.01*gib
	})
	if len(risks) != 1 {
		t.Fatalf("fill behind a sawtooth missed: %+v", risks)
	}
}

func TestStorageForecastResizeAndGapStartAgain(t *testing.T) {
	f := newForecastRun()
	if _, risks := f.hours("pvc:a/db", 30*gib, 48, func(i int) float64 { return 12*gib - float64(i)*0.025*gib }); len(risks) != 1 {
		t.Fatal("setup: no risk")
	}
	if ready, risks := f.sample("pvc:a/db", 60*gib, 37*gib); ready != 0 || len(risks) != 0 || len(f.history["pvc:a/db"]) != 1 {
		t.Fatal("a resized volume must start again")
	}
	f.at = f.at.Add(40 * time.Minute)
	if _, _ = f.sample("pvc:a/db", 60*gib, 37*gib); len(f.history["pvc:a/db"]) != 1 {
		t.Fatal("a gap must start again")
	}
}

// A node's disk holds container images, which the kubelet deletes once the
// disk is 85% full. It fills and empties by design and never runs out on a
// straight line, so it is not forecast at all.
func TestNodeDiskIsNotForecast(t *testing.T) {
	f := newForecastRun()
	// 75% used and filling steadily for two days (a day of deploys).
	ready, risks := f.hours("node:worker-1", 157*gib, 48, func(i int) float64 { return 39*gib - float64(i)*0.05*gib })
	if len(risks) != 0 {
		t.Fatalf("a node disk below the kubelet's threshold was reported: %+v", risks)
	}
	if ready != 1 {
		t.Fatalf("a node disk is judged from its first reading, ready=%d", ready)
	}
}

func TestNodeDiskAtRiskWhenTheKubeletCannotKeepUp(t *testing.T) {
	f := newForecastRun()
	f.hours("node:n1", 100*gib, 2, func(int) float64 { return 30 * gib })
	// Above 85% the kubelet should be reclaiming images. A moment there is normal.
	if _, risks := f.sample("node:n1", 100*gib, 14*gib); len(risks) != 0 {
		t.Fatalf("one reading above the image threshold reported: %+v", risks)
	}
	if _, risks := f.sample("node:n1", 100*gib, 14*gib); len(risks) != 0 {
		t.Fatalf("fifteen minutes above the image threshold reported: %+v", risks)
	}
	// Still there half an hour later: reclaiming is not keeping up.
	_, risks := f.sample("node:n1", 100*gib, 13*gib)
	if len(risks) != 1 || risks[0].Reason != riskPressure || risks[0].Key != "node:n1" || risks[0].Available != 13*gib {
		t.Fatalf("a node held above the image threshold not reported: %+v", risks)
	}
	// Reclaimed: fine again at once.
	if _, risks := f.sample("node:n1", 100*gib, 40*gib); len(risks) != 0 {
		t.Fatalf("a reclaimed node still reported: %+v", risks)
	}
	// At the eviction line there is nothing to wait for.
	if _, risks := f.sample("node:n1", 100*gib, 9*gib); len(risks) != 1 || risks[0].Reason != riskPressure {
		t.Fatalf("a node at the eviction line not reported at once: %+v", risks)
	}
}

func TestStorageForecastStableAndIndependentVolumes(t *testing.T) {
	history := map[string][]storagePoint{}
	start := time.Unix(1700000000, 0)
	for i := 0; i <= 200; i++ {
		ready, risks := updateStorageForecast(history, map[string]filesystemStats{
			"node:a":  {CapacityBytes: ptrFloat(1000), AvailableBytes: ptrFloat(300 + float64(i))},
			"pvc:n/b": {CapacityBytes: ptrFloat(1000), AvailableBytes: ptrFloat(450)},
		}, start.Add(time.Duration(i)*15*time.Minute))
		if len(risks) != 0 {
			t.Fatal("stable or shrinking usage must not alert")
		}
		if i == 200 && ready != 2 {
			t.Fatal("independent windows not ready")
		}
	}
	updateStorageForecast(history, map[string]filesystemStats{}, start.Add(60*time.Hour))
	if len(history) != 0 {
		t.Fatal("stale filesystems retained")
	}
}

func TestStorageRiskLabels(t *testing.T) {
	got := storageRiskLabels(storageRisk{Key: "pvc:prod/postgres-2", Reason: riskFilling}, map[string]string{"pvc:prod/postgres-2": "postgres-2"})
	want := map[string]string{"kind": "volume", "namespace": "prod", "name": "postgres-2", "reason": "filling", "pod": "postgres-2"}
	if len(got) != len(want) {
		t.Fatalf("labels %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("labels %v, want %v", got, want)
		}
	}
	node := storageRiskLabels(storageRisk{Key: "node:worker-1", Reason: riskPressure}, nil)
	if node["kind"] != "node" || node["name"] != "worker-1" || node["reason"] != "pressure" || len(node) != 3 {
		t.Fatalf("node labels %v", node)
	}
}
