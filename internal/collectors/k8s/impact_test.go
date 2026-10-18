package k8s

import (
	"testing"
	"time"
)

func TestWorkloadHealth(t *testing.T) {
	cases := []struct {
		name           string
		w              workloadState
		rolloutExpired bool
		wantHealthy    bool
		wantReason     string
	}{
		{"fully available", workloadState{desired: 3, available: 3, updated: 3}, false, true, ""},
		{"more available than desired (scaling down)", workloadState{desired: 2, available: 3, updated: 2}, false, true, ""},
		{"deliberately scaled to zero", workloadState{desired: 0, available: 0}, false, true, ""},
		{"partially available", workloadState{desired: 3, available: 1, updated: 3}, false, false, "Degraded"},
		{"nothing available", workloadState{desired: 3, available: 0, updated: 3}, false, false, "Unavailable"},
		{"mid-rollout dip is not degraded", workloadState{desired: 3, available: 1, updated: 1, rollingOut: true}, false, true, ""},
		// A rollout is not an indefinite alibi: past the grace it reports.
		{"stuck rollout past its grace", workloadState{desired: 3, available: 0, updated: 1, rollingOut: true}, true, false, "Unavailable"},
		{"stuck rollout, partially up", workloadState{desired: 3, available: 1, updated: 1, rollingOut: true}, true, false, "Degraded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := workloadHealth(tc.w, tc.rolloutExpired)
			if hs.healthy != tc.wantHealthy {
				t.Fatalf("healthy = %v, want %v (%+v)", hs.healthy, tc.wantHealthy, tc.w)
			}
			if !tc.wantHealthy && hs.reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", hs.reason, tc.wantReason)
			}
		})
	}
}

func TestIsRollingOut(t *testing.T) {
	// Controller has not yet observed the new spec.
	if !isRollingOut(ObjectMeta{Generation: 5}, 4, 3, 3) {
		t.Error("observedGeneration behind generation should be rolling out")
	}
	// Converged and fully updated.
	if isRollingOut(ObjectMeta{Generation: 5}, 5, 3, 3) {
		t.Error("converged workload should not be rolling out")
	}
	// Still replacing pods with the new template.
	if !isRollingOut(ObjectMeta{Generation: 5}, 5, 1, 3) {
		t.Error("updated < desired should be rolling out")
	}
}

// An object fault surfaces only when its workload is degraded.
func TestPodFaultDemotedWhenWorkloadHealthy(t *testing.T) {
	newCollector := func() *Collector {
		c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
		c.replicaSets = newReflector(c.client, "/apis/apps/v1/replicasets",
			func(r ReplicaSet) string { return r.key() }, c.logger, nil)
		c.replicaSets.store.put("ns/app-abc", ReplicaSet{Metadata: ObjectMeta{
			Namespace: "ns", Name: "app-abc",
			OwnerReferences: []OwnerReference{{Kind: "Deployment", Name: "app", Controller: boolPtr(true)}},
		}})
		return c
	}

	crashingPod := []Pod{{
		Metadata: ObjectMeta{Namespace: "ns", Name: "app-abc-1",
			OwnerReferences: []OwnerReference{{Kind: "ReplicaSet", Name: "app-abc", Controller: boolPtr(true)}}},
		Status: PodStatus{Phase: "Running", ContainerStatuses: []ContainerStatus{
			{Name: "c", State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}},
	}}

	surfaceOfPod := func(obs []observation) bool {
		for _, o := range obs {
			if o.kind == "pod" && o.name == "app-abc-1" {
				return o.surface
			}
		}
		t.Fatal("pod observation missing")
		return false
	}

	// Workload fully available: the crash is an anomaly, not an incident.
	healthy := []workloadState{{kind: "Deployment", namespace: "ns", name: "app",
		desired: 3, available: 3, updated: 3}}
	obs, counts := newCollector().observe(crashingPod, nil, nil, healthy, nil, nil, time.Now())
	if surfaceOfPod(obs) {
		t.Error("a CrashLooping pod must not surface while its workload is fully available")
	}
	if counts.podsFailing != 1 {
		t.Errorf("dashboard should still count the failing pod, got %d", counts.podsFailing)
	}
	if counts.suppressed != 1 {
		t.Errorf("expected the fault to be counted as suppressed, got %d", counts.suppressed)
	}

	// Same pod with its workload degraded: it surfaces.
	degraded := []workloadState{{kind: "Deployment", namespace: "ns", name: "app",
		desired: 3, available: 1, updated: 3}}
	obs2, _ := newCollector().observe(crashingPod, nil, nil, degraded, nil, nil, time.Now())
	if !surfaceOfPod(obs2) {
		t.Error("the same pod must surface once its workload is degraded")
	}
}

// A pod with no controller has no availability to hide behind.
func TestBarePodStillSurfaces(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	c.replicaSets = newReflector(c.client, "/apis/apps/v1/replicasets",
		func(r ReplicaSet) string { return r.key() }, c.logger, nil)

	bare := []Pod{{
		Metadata: ObjectMeta{Namespace: "ns", Name: "standalone"},
		Status: PodStatus{Phase: "Running", ContainerStatuses: []ContainerStatus{
			{Name: "c", State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}},
	}}
	obs, _ := c.observe(bare, nil, nil, nil, nil, nil, time.Now())
	for _, o := range obs {
		if o.kind == "pod" && !o.surface {
			t.Error("a bare CrashLooping pod must surface: it has no workload to fall back on")
		}
	}
}

func TestPerNamespaceCounts(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	c.replicaSets = newReflector(c.client, "/apis/apps/v1/replicasets",
		func(r ReplicaSet) string { return r.key() }, c.logger, nil)

	pods := []Pod{
		{Metadata: ObjectMeta{Namespace: "shop", Name: "a"}, Status: PodStatus{Phase: "Running"}},
		{Metadata: ObjectMeta{Namespace: "shop", Name: "b"}, Status: PodStatus{Phase: "Pending"}},
		{Metadata: ObjectMeta{Namespace: "blog", Name: "c"}, Status: PodStatus{Phase: "Running"}},
	}
	_, counts := c.observe(pods, nil, nil, nil, nil, nil, time.Now())

	if counts.byNamespace["shop"].podsRunning != 1 || counts.byNamespace["shop"].podsPending != 1 {
		t.Errorf("shop counts wrong: %+v", counts.byNamespace["shop"])
	}
	if counts.byNamespace["blog"].podsRunning != 1 {
		t.Errorf("blog counts wrong: %+v", counts.byNamespace["blog"])
	}
}

func boolPtrT(b bool) *bool { return &b }

func TestPdbHealth(t *testing.T) {
	// A tight but correct PDB (minAvailable == replicas) sits at zero allowed
	// disruptions indefinitely. That is not a violation.
	tightButHealthy := PodDisruptionBudget{Status: PDBStatus{
		CurrentHealthy: 3, DesiredHealthy: 3, DisruptionsAllowed: 0, ExpectedPods: 3}}
	if hs := pdbHealth(tightButHealthy); !hs.healthy {
		t.Fatalf("a PDB at zero headroom but fully healthy must not alert, got %+v", hs)
	}

	violated := PodDisruptionBudget{Status: PDBStatus{
		CurrentHealthy: 1, DesiredHealthy: 3, DisruptionsAllowed: 0, ExpectedPods: 3}}
	hs := pdbHealth(violated)
	if hs.healthy || hs.reason != "PDBViolated" {
		t.Fatalf("a PDB below its desired healthy count must alert, got %+v", hs)
	}

	// Nothing declared: nothing to violate.
	if hs := pdbHealth(PodDisruptionBudget{}); !hs.healthy {
		t.Fatal("an empty PDB status must not alert")
	}
}

func TestEndpointsHealth(t *testing.T) {
	// No endpoints at all = scaled to zero or headless, not an outage.
	if hs := endpointsHealth(serviceEndpoints{total: 0, ready: 0}); !hs.healthy {
		t.Fatal("a Service with no endpoints must not alert (scaled to zero)")
	}
	// Endpoints exist but none serve = traffic has nowhere to land.
	hs := endpointsHealth(serviceEndpoints{total: 3, ready: 0})
	if hs.healthy || hs.reason != "NoReadyEndpoints" {
		t.Fatalf("a Service with endpoints but none ready must alert, got %+v", hs)
	}
	if hs := endpointsHealth(serviceEndpoints{total: 3, ready: 1}); !hs.healthy {
		t.Fatal("partially ready endpoints still serve traffic; workload availability covers degradation")
	}
}

func TestAggregateEndpointSlices(t *testing.T) {
	slices := []EndpointSlice{
		{Metadata: ObjectMeta{Namespace: "shop", Name: "a-1",
			Labels: map[string]string{"kubernetes.io/service-name": "shop"}},
			Endpoints: []Endpoint{{Conditions: EndpointConditions{Ready: boolPtrT(true)}},
				{Conditions: EndpointConditions{Ready: boolPtrT(false)}}}},
		{Metadata: ObjectMeta{Namespace: "shop", Name: "a-2",
			Labels: map[string]string{"kubernetes.io/service-name": "shop"}},
			Endpoints: []Endpoint{{Conditions: EndpointConditions{Ready: boolPtrT(true)}}}},
		// No service-name label: skipped entirely.
		{Metadata: ObjectMeta{Namespace: "shop", Name: "orphan"},
			Endpoints: []Endpoint{{}}},
	}
	got := aggregateEndpointSlices(slices)
	if len(got) != 1 {
		t.Fatalf("expected 1 aggregated service, got %d (%+v)", len(got), got)
	}
	if got[0].total != 3 || got[0].ready != 2 {
		t.Fatalf("expected 3 total / 2 ready, got %+v", got[0])
	}
	// An absent ready condition means ready, per the API contract.
	if !(Endpoint{}).ready() {
		t.Fatal("an endpoint with no ready condition must count as ready")
	}
}

func TestImpactMustBeSustained(t *testing.T) {
	p := defaultNoisePolicy()
	// A momentary dip is not an incident...
	if p.surface("Unavailable", 5*time.Second, false) {
		t.Error("a brief availability dip must not surface")
	}
	// ...but sustained impact is, and a reclaim does not excuse it.
	if !p.surface("Unavailable", 5*time.Minute, false) {
		t.Error("sustained unavailability must surface")
	}
	if !p.surface("Unavailable", 5*time.Minute, true) {
		t.Error("real impact must surface even during a reclaim window")
	}
	if classify("PDBViolated") != classImpact || classify("NoReadyEndpoints") != classImpact {
		t.Error("PDB and endpoint reasons must be treated as service impact")
	}
}

// Two namespaces each run a Deployment called "api". One is down; the other is
// fully available with one crash-looping pod. Targets are namespace-qualified,
// so the outage in "shop" neither surfaces the healthy namespace's pod nor
// merges with it.
func TestSameNamedWorkloadsInDifferentNamespacesStayApart(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	c.replicaSets = newReflector(c.client, "/apis/apps/v1/replicasets",
		func(r ReplicaSet) string { return r.key() }, c.logger, nil)
	for _, ns := range []string{"shop", "blog"} {
		c.replicaSets.store.put(ns+"/api-abc", ReplicaSet{Metadata: ObjectMeta{
			Namespace: ns, Name: "api-abc",
			OwnerReferences: []OwnerReference{{Kind: "Deployment", Name: "api", Controller: boolPtr(true)}},
		}})
	}
	crashing := Pod{
		Metadata: ObjectMeta{Namespace: "blog", Name: "api-abc-1",
			OwnerReferences: []OwnerReference{{Kind: "ReplicaSet", Name: "api-abc", Controller: boolPtr(true)}}},
		Status: PodStatus{Phase: "Running", ContainerStatuses: []ContainerStatus{
			{Name: "c", State: ContainerState{Waiting: &ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}},
	}
	workloads := []workloadState{
		{kind: "Deployment", namespace: "shop", name: "api", desired: 3, available: 0, updated: 3},
		{kind: "Deployment", namespace: "blog", name: "api", desired: 3, available: 3, updated: 3},
	}
	now := time.Now()
	obs, counts := c.observe([]Pod{crashing}, nil, nil, workloads, nil, nil, now)

	for _, o := range obs {
		if o.kind == "pod" && o.surface {
			t.Error("blog's pod surfaced because shop's same-named Deployment is down")
		}
	}
	if counts.workloadsTotal != 2 {
		t.Errorf("workloads total = %d; two namespaces' api are two workloads", counts.workloadsTotal)
	}

	// Let the shop outage outlast the noise policy, then check the identity
	// that goes on the wire.
	c.diff(obs, now, nil)
	obs, counts = c.observe([]Pod{crashing}, nil, nil, workloads, nil, nil, now.Add(10*time.Minute))
	c.diff(obs, now.Add(10*time.Minute), nil)
	if got := c.activeTargets(); len(got) != 1 || got[0] != "shop/Deployment/api" {
		t.Fatalf("active targets = %v, want [shop/Deployment/api]", got)
	}
	if len(counts.degraded) != 1 || counts.degraded[0] != "shop/Deployment/api" {
		t.Fatalf("degraded = %v, want [shop/Deployment/api]", counts.degraded)
	}
	for _, o := range obs {
		if o.kind == "workload" && o.namespace == "shop" && o.owner != "Deployment/api" {
			t.Errorf("owner = %q; the delta's owner stays Kind/name next to its namespace", o.owner)
		}
	}
}
