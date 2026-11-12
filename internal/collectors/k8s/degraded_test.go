package k8s

import (
	"testing"
	"time"
)

// A failed run of a CronJob is the scheduled-job alert's to report, with the
// run and the reason. Counting it as a degraded workload as well sent a
// second, vaguer alert for every failed backup.
func TestAFailedCronJobRunIsNotADegradedWorkload(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	jobs := []Job{ownedJob("laborpad", "laborpad-db-backup", "2026-11-12T08:40:00Z", "Failed")}
	_, counts := c.observe(nil, nil, jobs, nil, nil, nil, time.Now())
	if counts.jobsFailing != 1 {
		t.Errorf("jobsFailing = %d, want 1", counts.jobsFailing)
	}
	if len(counts.degraded) != 0 {
		t.Errorf("degraded = %v; a failed CronJob run is not a degraded workload", counts.degraded)
	}
}

func TestADegradedWorkloadSaysHowAndWhy(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	c.replicaSets = newReflector(c.client, "/apis/apps/v1/replicasets",
		func(r ReplicaSet) string { return r.key() }, c.logger, nil)
	c.replicaSets.store.put("shop/api-7d9f", ReplicaSet{Metadata: ObjectMeta{Namespace: "shop", Name: "api-7d9f",
		OwnerReferences: []OwnerReference{{Kind: "Deployment", Name: "api", Controller: boolPtr(true)}}}})
	crashing := Pod{
		Metadata: ObjectMeta{Namespace: "shop", Name: "api-7d9f-x1",
			OwnerReferences: []OwnerReference{{Kind: "ReplicaSet", Name: "api-7d9f", Controller: boolPtr(true)}}},
		Status: PodStatus{Phase: "Running", ContainerStatuses: []ContainerStatus{
			{Name: "api", RestartCount: 7, State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "back-off 5m0s restarting failed container"}}}}},
	}
	workloads := []workloadState{{kind: "Deployment", namespace: "shop", name: "api", desired: 3, available: 1, updated: 3}}
	now := time.Now()
	c.observe([]Pod{crashing}, nil, nil, workloads, nil, nil, now)
	_, counts := c.observe([]Pod{crashing}, nil, nil, workloads, nil, nil, now.Add(10*time.Minute))

	if len(counts.degraded) != 1 {
		t.Fatalf("degraded = %v", counts.degraded)
	}
	series := degradedWorkloadSeries(counts)
	if len(series) != 1 {
		t.Fatalf("series %v", series)
	}
	want := map[string]string{"namespace": "shop", "workload": "Deployment/api", "reason": "Degraded",
		"message": "1 of 3 replicas available", "desired": "3", "available": "1",
		"pod": "api-7d9f-x1", "pod_reason": "CrashLoopBackOff"}
	for k, v := range want {
		if series[0][k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, series[0][k], v, series[0])
		}
	}
}
