package k8s

import (
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := map[string]reasonClass{
		"CrashLoopBackOff":      classImmediate,
		"OOMKilled":             classImmediate,
		"Init:ImagePullBackOff": classImmediate, // Init: prefix stripped
		"Unschedulable":         classReschedule,
		"Pending":               classReschedule,
		"Evicted":               classReschedule,
		"NotReady":              classNodeGraced,
		"MemoryPressure":        classNodeGraced,
		"Cordoned":              classSuppressed,
		"SomethingUnknown":      classImmediate, // fail safe = surface
	}
	for reason, want := range cases {
		if got := classify(reason); got != want {
			t.Errorf("classify(%q) = %d, want %d", reason, got, want)
		}
	}
}

func TestNoisePolicySurface(t *testing.T) {
	p := defaultNoisePolicy()
	brief := 10 * time.Second
	long := 10 * time.Minute

	if !p.surface("CrashLoopBackOff", brief, true) {
		t.Error("CrashLoopBackOff must surface even during a reclaim")
	}
	if !p.surface("OOMKilled", brief, false) {
		t.Error("OOMKilled must surface immediately")
	}

	if p.surface("Cordoned", long, false) {
		t.Error("Cordoned must never surface")
	}

	// Transient churn is suppressed while a reclaim window is open, but
	// surfaces once it persists past the grace with no reclaim.
	if p.surface("Unschedulable", brief, true) {
		t.Error("Unschedulable during a reclaim must be suppressed")
	}
	if p.surface("Evicted", long, true) {
		t.Error("Evicted during a reclaim must be suppressed")
	}
	if p.surface("Unschedulable", brief, false) {
		t.Error("briefly-Unschedulable (no reclaim) should still be within grace")
	}
	if !p.surface("Unschedulable", long, false) {
		t.Error("long-Unschedulable with no reclaim must surface (genuine capacity problem)")
	}

	if p.surface("NotReady", brief, false) {
		t.Error("a brief NotReady blip must not surface")
	}
	if !p.surface("NotReady", long, false) {
		t.Error("a sustained NotReady must surface")
	}
}

// TestReclaimSuppressesRescheduleChurn drives observe end to end: after a node
// vanishes, a pod that goes Unschedulable is not surfaced, while a
// crash-looping pod in the same window is.
func TestReclaimSuppressesRescheduleChurn(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	// Stub the store a reflector would own so observe runs without watchers.
	c.replicaSets = newReflector(c.client, "/apis/apps/v1/replicasets",
		func(r ReplicaSet) string { return r.key() }, c.logger, nil)

	now := time.Now()

	// Cycle 1: two nodes present, everything healthy. Seeds lastNodeKeys.
	nodes := []Node{
		{Metadata: ObjectMeta{Name: "node-a"}, Status: NodeStatus{Conditions: []NodeCondition{{Type: "Ready", Status: "True"}}}},
		{Metadata: ObjectMeta{Name: "node-b"}, Status: NodeStatus{Conditions: []NodeCondition{{Type: "Ready", Status: "True"}}}},
	}
	c.trackNodeRemovals(nodes, now)
	c.observe(nil, nodes, nil, nil, nil, nil, now)

	// Cycle 2: node-b is gone. One pod is Unschedulable and an unrelated pod
	// is crash-looping.
	nodes = nodes[:1]
	pods := []Pod{
		{Metadata: ObjectMeta{Namespace: "ns", Name: "resched"},
			Status: PodStatus{Phase: "Pending", Conditions: []PodCondition{
				{Type: "PodScheduled", Status: "False", Reason: "Unschedulable"}}}},
		{Metadata: ObjectMeta{Namespace: "ns", Name: "crash"},
			Status: PodStatus{Phase: "Running", ContainerStatuses: []ContainerStatus{
				{Name: "app", State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}}},
	}
	c.trackNodeRemovals(nodes, now.Add(time.Second))
	obs, counts := c.observe(pods, nodes, nil, nil, nil, nil, now.Add(time.Second))

	var reschedSurfaced, crashSurfaced bool
	for _, o := range obs {
		if o.name == "resched" {
			reschedSurfaced = o.surface
		}
		if o.name == "crash" {
			crashSurfaced = o.surface
		}
	}
	if reschedSurfaced {
		t.Error("an Unschedulable pod during a reclaim window must be suppressed")
	}
	if !crashSurfaced {
		t.Error("a CrashLooping pod must surface even during a reclaim window")
	}
	if c.nodeCycles.Load() != 1 {
		t.Errorf("expected 1 node cycle recorded, got %d", c.nodeCycles.Load())
	}
	if counts.suppressed != 1 {
		t.Errorf("expected 1 suppressed finding, got %d", counts.suppressed)
	}
	// Health counts are unaffected by suppression.
	if counts.podsFailing != 2 {
		t.Errorf("dashboard should count both failing pods, got %d", counts.podsFailing)
	}
}
