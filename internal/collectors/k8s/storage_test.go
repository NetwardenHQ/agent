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

func TestStorageForecastWarmupGrowthResizeAndGap(t *testing.T) {
	history := map[string][]storagePoint{}
	start := time.Unix(1700000000, 0)
	sample := func(at time.Time, capacity, available float64) (int, int) {
		return updateStorageForecast(history, map[string]filesystemStats{"pvc:db": {CapacityBytes: ptrFloat(capacity), AvailableBytes: ptrFloat(available)}}, at)
	}
	if ready, risk := sample(start, 1000, 500); ready != 0 || risk != 0 {
		t.Fatal("forecast before history")
	}
	for i := 1; i <= 72; i++ {
		sample(start.Add(time.Duration(i)*5*time.Minute), 1000, 500-float64(i))
	}
	ready, risk := sample(start.Add(365*time.Minute), 1000, 427)
	if ready != 1 || risk != 1 {
		t.Fatalf("growth forecast: %d %d", ready, risk)
	}
	if ready, risk = sample(start.Add(370*time.Minute), 2000, 1420); ready != 0 || risk != 0 {
		t.Fatal("resize must reset")
	}
	if ready, _ = sample(start.Add(410*time.Minute), 2000, 1400); ready != 0 || len(history["pvc:db"]) != 1 {
		t.Fatal("gap must reset")
	}
}
func TestStorageForecastStableAndIndependentVolumes(t *testing.T) {
	history := map[string][]storagePoint{}
	start := time.Unix(1700000000, 0)
	for i := 0; i <= 72; i++ {
		ready, risk := updateStorageForecast(history, map[string]filesystemStats{
			"node:a": {CapacityBytes: ptrFloat(1000), AvailableBytes: ptrFloat(100 + float64(i))},
			"pvc:b":  {CapacityBytes: ptrFloat(1000), AvailableBytes: ptrFloat(450)},
		}, start.Add(time.Duration(i)*5*time.Minute))
		if risk != 0 {
			t.Fatal("stable or shrinking usage must not alert")
		}
		if i == 72 && ready != 2 {
			t.Fatal("independent windows not ready")
		}
	}
	updateStorageForecast(history, map[string]filesystemStats{}, start.Add(8*time.Hour))
	if len(history) != 0 {
		t.Fatal("stale filesystems retained")
	}
}
