package k8s

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func boolPtr(b bool) *bool { return &b }

func TestPodHealth(t *testing.T) {
	now := time.Now()
	threshold := 5 * time.Minute

	cases := []struct {
		name        string
		pod         Pod
		wantHealthy bool
		wantReason  string
	}{
		{
			name: "running and ready",
			pod: Pod{Status: PodStatus{Phase: "Running",
				ContainerStatuses: []ContainerStatus{{Name: "app", Ready: true}}}},
			wantHealthy: true,
		},
		{
			name: "crashloop",
			pod: Pod{Status: PodStatus{Phase: "Running", ContainerStatuses: []ContainerStatus{
				{Name: "app", Ready: false, RestartCount: 7,
					State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}}},
			wantHealthy: false, wantReason: "CrashLoopBackOff",
		},
		{
			name: "imagepull",
			pod: Pod{Status: PodStatus{Phase: "Pending", ContainerStatuses: []ContainerStatus{
				{Name: "app", State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "ImagePullBackOff"}}}}}},
			wantHealthy: false, wantReason: "ImagePullBackOff",
		},
		{
			name: "oomkilled",
			pod: Pod{Status: PodStatus{Phase: "Running", ContainerStatuses: []ContainerStatus{
				{Name: "app", Ready: false,
					State: ContainerState{Terminated: &ContainerStateTerminated{Reason: "OOMKilled"}}}}}},
			wantHealthy: false, wantReason: "OOMKilled",
		},
		{
			name: "unschedulable",
			pod: Pod{Status: PodStatus{Phase: "Pending", Conditions: []PodCondition{
				{Type: "PodScheduled", Status: "False", Reason: "Unschedulable", Message: "0/6 nodes available"}}}},
			wantHealthy: false, wantReason: "Unschedulable",
		},
		{
			name:        "evicted",
			pod:         Pod{Status: PodStatus{Phase: "Failed", Reason: "Evicted", Message: "node under memory pressure"}},
			wantHealthy: false, wantReason: "Evicted",
		},
		{
			name:        "succeeded job pod",
			pod:         Pod{Status: PodStatus{Phase: "Succeeded"}},
			wantHealthy: true,
		},
		{
			name: "young pending is not yet a problem",
			pod: Pod{
				Metadata: ObjectMeta{CreationTimestamp: now.Add(-30 * time.Second).UTC().Format(time.RFC3339)},
				Status:   PodStatus{Phase: "Pending"},
			},
			wantHealthy: true,
		},
		{
			name: "old pending is a problem",
			pod: Pod{
				Metadata: ObjectMeta{CreationTimestamp: now.Add(-10 * time.Minute).UTC().Format(time.RFC3339)},
				Status:   PodStatus{Phase: "Pending"},
			},
			wantHealthy: false, wantReason: "Pending",
		},
		{
			name: "failing init container",
			pod: Pod{Status: PodStatus{Phase: "Pending", InitContainerStatuses: []ContainerStatus{
				{Name: "init", State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}}},
			wantHealthy: false, wantReason: "Init:CrashLoopBackOff",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs, _ := podHealth(tc.pod, now, threshold)
			if hs.healthy != tc.wantHealthy {
				t.Fatalf("healthy = %v, want %v", hs.healthy, tc.wantHealthy)
			}
			if !tc.wantHealthy && hs.reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", hs.reason, tc.wantReason)
			}
		})
	}
}

func TestNodeHealth(t *testing.T) {
	ready := Node{Status: NodeStatus{Conditions: []NodeCondition{{Type: "Ready", Status: "True"}}}}
	if hs := nodeHealth(ready); !hs.healthy {
		t.Fatalf("ready node should be healthy, got %+v", hs)
	}

	notReady := Node{Status: NodeStatus{Conditions: []NodeCondition{{Type: "Ready", Status: "Unknown", Reason: "NodeStatusUnknown"}}}}
	if hs := nodeHealth(notReady); hs.healthy || hs.reason != "NodeStatusUnknown" {
		t.Fatalf("unknown-ready node should be NotReady-ish, got %+v", hs)
	}

	pressured := Node{Status: NodeStatus{Conditions: []NodeCondition{
		{Type: "Ready", Status: "True"}, {Type: "MemoryPressure", Status: "True"}}}}
	if hs := nodeHealth(pressured); hs.healthy || hs.reason != "MemoryPressure" {
		t.Fatalf("pressured node should surface pressure, got %+v", hs)
	}
	if !nodePressured(pressured) {
		t.Fatal("nodePressured should be true for a Ready+MemoryPressure node")
	}
	if !nodeReady(pressured) {
		t.Fatal("nodeReady should be true even under pressure")
	}

	cordoned := Node{
		Spec:   NodeSpec{Unschedulable: true},
		Status: NodeStatus{Conditions: []NodeCondition{{Type: "Ready", Status: "True"}}}}
	if hs := nodeHealth(cordoned); hs.healthy || hs.reason != "Cordoned" {
		t.Fatalf("cordoned node should surface Cordoned, got %+v", hs)
	}
}

func TestWorkloadOwnerResolvesReplicaSetToDeployment(t *testing.T) {
	rsStore := newStore[ReplicaSet]()
	rsStore.put("shop/web-7c9d", ReplicaSet{Metadata: ObjectMeta{
		Namespace: "shop", Name: "web-7c9d",
		OwnerReferences: []OwnerReference{{Kind: "Deployment", Name: "web", Controller: boolPtr(true)}},
	}})

	pod := Pod{Metadata: ObjectMeta{Namespace: "shop", Name: "web-7c9d-x2k",
		OwnerReferences: []OwnerReference{{Kind: "ReplicaSet", Name: "web-7c9d", Controller: boolPtr(true)}}}}

	if got := workloadOwner(pod, rsStore); got != "Deployment/web" {
		t.Fatalf("owner = %q, want Deployment/web", got)
	}

	// A Job-owned pod rolls up directly to the Job.
	jobPod := Pod{Metadata: ObjectMeta{Namespace: "shop", Name: "backup-abc",
		OwnerReferences: []OwnerReference{{Kind: "Job", Name: "db-backup-29", Controller: boolPtr(true)}}}}
	if got := workloadOwner(jobPod, rsStore); got != "Job/db-backup-29" {
		t.Fatalf("owner = %q, want Job/db-backup-29", got)
	}

	// A ReplicaSet with no Deployment owner falls back to the ReplicaSet.
	orphanRS := newStore[ReplicaSet]()
	orphanRS.put("x/bare-rs", ReplicaSet{Metadata: ObjectMeta{Namespace: "x", Name: "bare-rs"}})
	orphanPod := Pod{Metadata: ObjectMeta{Namespace: "x", Name: "bare-rs-1",
		OwnerReferences: []OwnerReference{{Kind: "ReplicaSet", Name: "bare-rs", Controller: boolPtr(true)}}}}
	if got := workloadOwner(orphanPod, orphanRS); got != "ReplicaSet/bare-rs" {
		t.Fatalf("owner = %q, want ReplicaSet/bare-rs", got)
	}
}

func TestDiffEmitsTransitions(t *testing.T) {
	c := NewCollector("h")
	now := time.Now()

	// First sight of an unhealthy pod → one "unhealthy" transition.
	obs := []observation{{key: "pod|ns|a", kind: "pod", namespace: "ns", name: "a",
		healthy: false, surface: true, reason: "CrashLoopBackOff", owner: "Deployment/a"}}
	tr := c.diff(obs, now, nil)
	if len(tr) != 1 || tr[0]["state"] != "unhealthy" {
		t.Fatalf("expected one unhealthy transition, got %+v", tr)
	}

	// Same state next cycle → no transition (no re-alert).
	if tr := c.diff(obs, now, nil); len(tr) != 0 {
		t.Fatalf("expected no transition on unchanged state, got %+v", tr)
	}

	// Pod recovers → one "recovered" transition.
	healthy := []observation{{key: "pod|ns|a", kind: "pod", namespace: "ns", name: "a", healthy: true, surface: false}}
	tr = c.diff(healthy, now, nil)
	if len(tr) != 1 || tr[0]["state"] != "recovered" {
		t.Fatalf("expected one recovered transition, got %+v", tr)
	}
}

// A termination message is truncated on a rune boundary.
func TestContainerMessageIsTruncated(t *testing.T) {
	long := strings.Repeat("é", maxMessageRunes+50)
	cs := ContainerStatus{State: ContainerState{Terminated: &ContainerStateTerminated{Reason: "OOMKilled", Message: long}}}
	hs, ok := containerProblem(cs)
	if !ok {
		t.Fatal("OOMKilled not detected")
	}
	if !utf8.ValidString(hs.message) {
		t.Fatal("truncation split a rune")
	}
	if n := utf8.RuneCountInString(hs.message); n != maxMessageRunes+1 { // + the ellipsis
		t.Fatalf("message is %d runes", n)
	}
	if short := truncateMessage("exit 137"); short != "exit 137" {
		t.Fatalf("a short message was altered: %q", short)
	}
}
