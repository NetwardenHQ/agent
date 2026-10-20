package k8s

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// This file derives health from API objects: whether an object is healthy and,
// if not, why. It does no I/O so it can be tested against captured status shapes.

// healthState is the derived verdict for one object.
type healthState struct {
	healthy bool
	reason  string
	message string
}

// badWaitingReasons are container Waiting reasons that mean a real failure, not
// a transient startup. A container Waiting for any of these is unhealthy.
var badWaitingReasons = map[string]bool{
	"CrashLoopBackOff":           true,
	"ImagePullBackOff":           true,
	"ErrImagePull":               true,
	"InvalidImageName":           true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"RunContainerError":          true,
	"CtrOOMKilled":               true,
}

// podHealth derives a pod's health. It returns the verdict plus the summed
// restart count across containers (surfaced in the delta). pendingThreshold is
// how long a pod may sit Pending before that is treated as a failure; a young
// Pending pod is still starting.
func podHealth(p Pod, now time.Time, pendingThreshold time.Duration) (healthState, int) {
	restarts := 0
	for _, cs := range p.Status.ContainerStatuses {
		restarts += cs.RestartCount
	}

	// A node-pressure eviction surfaces as phase Failed, reason Evicted.
	if strings.EqualFold(p.Status.Reason, "Evicted") {
		return healthState{false, "Evicted", p.Status.Message}, restarts
	}

	switch p.Status.Phase {
	case "Succeeded":
		// A completed pod (e.g. a Job pod) is not a problem.
		return healthState{true, "", ""}, restarts
	case "Failed":
		reason := p.Status.Reason
		if reason == "" {
			reason = "Failed"
		}
		return healthState{false, reason, p.Status.Message}, restarts
	}

	// Container-level problems apply whether the pod is Pending or Running.
	// Init containers are checked first: a failing init container blocks the
	// whole pod and is the more actionable signal.
	for _, cs := range p.Status.InitContainerStatuses {
		if s, ok := containerProblem(cs); ok {
			return healthState{false, "Init:" + s.reason, s.message}, restarts
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		if s, ok := containerProblem(cs); ok {
			return healthState{false, s.reason, s.message}, restarts
		}
	}

	if p.Status.Phase == "Pending" {
		// Unschedulable is a problem regardless of age: the scheduler has
		// actively failed to place the pod.
		for _, cond := range p.Status.Conditions {
			if cond.Type == "PodScheduled" && cond.Status == "False" && cond.Reason == "Unschedulable" {
				return healthState{false, "Unschedulable", cond.Message}, restarts
			}
		}
		if podAge(p, now) > pendingThreshold {
			return healthState{false, "Pending", "pod has not started"}, restarts
		}
	}

	return healthState{true, "", ""}, restarts
}

// containerProblem inspects one container status for a failure worth surfacing.
func containerProblem(cs ContainerStatus) (healthState, bool) {
	if w := cs.State.Waiting; w != nil && badWaitingReasons[w.Reason] {
		return healthState{false, w.Reason, truncateMessage(w.Message)}, true
	}
	if t := cs.State.Terminated; t != nil && t.Reason == "OOMKilled" {
		return healthState{false, "OOMKilled", truncateMessage(t.Message)}, true
	}
	// A container caught between OOM kills sits Waiting=CrashLoopBackOff (caught
	// above) with the OOM in lastState; surface OOM specifically when the
	// container is not currently ready, which is the more precise cause.
	if t := cs.LastState.Terminated; t != nil && t.Reason == "OOMKilled" && !cs.Ready {
		return healthState{false, "OOMKilled", truncateMessage(t.Message)}, true
	}
	return healthState{}, false
}

// maxMessageRunes bounds a container message before it is shipped.
const maxMessageRunes = 256

// truncateMessage bounds a container-supplied message. A termination message is
// whatever the container wrote to its terminationMessagePath (up to 4 KiB per
// container, possibly a stack trace or a log tail), and it is copied into
// every delta and finding. The cut is on a rune boundary, and invalid UTF-8 is
// dropped, so the result is always valid JSON text.
func truncateMessage(s string) string {
	s = strings.ToValidUTF8(s, "")
	if utf8.RuneCountInString(s) <= maxMessageRunes {
		return s
	}
	n := 0
	for i := range s {
		if n == maxMessageRunes {
			return s[:i] + "…"
		}
		n++
	}
	return s
}

// nodeHealth derives a node's health, preferring the most severe signal:
// NotReady (lost/broken) over resource pressure over an intentional cordon.
func nodeHealth(n Node) healthState {
	var ready *NodeCondition
	var pressure string
	for i := range n.Status.Conditions {
		cond := &n.Status.Conditions[i]
		switch cond.Type {
		case "Ready":
			ready = cond
		case "MemoryPressure", "DiskPressure", "PIDPressure":
			if cond.Status == "True" && pressure == "" {
				pressure = cond.Type
			}
		}
	}

	if ready == nil || ready.Status != "True" {
		reason := "NotReady"
		msg := ""
		if ready != nil {
			if ready.Reason != "" {
				reason = ready.Reason
			}
			msg = ready.Message
		}
		return healthState{false, reason, msg}
	}
	if pressure != "" {
		return healthState{false, pressure,
			"node under " + strings.ToLower(strings.TrimSuffix(pressure, "Pressure")) + " pressure"}
	}
	if n.Spec.Unschedulable {
		return healthState{false, "Cordoned", "node is cordoned (SchedulingDisabled)"}
	}
	return healthState{true, "", ""}
}

// nodePressured reports whether a node is Ready but under resource pressure.
// It feeds the cluster-health "pressured" count, which is distinct from NotReady.
func nodePressured(n Node) bool {
	ready := false
	pressure := false
	for _, cond := range n.Status.Conditions {
		switch cond.Type {
		case "Ready":
			ready = cond.Status == "True"
		case "MemoryPressure", "DiskPressure", "PIDPressure":
			if cond.Status == "True" {
				pressure = true
			}
		}
	}
	return ready && pressure
}

// podAge returns how long the pod has existed, from its creationTimestamp.
// An unparseable timestamp yields 0 (treated as brand new, hence not flagged).
func podAge(p Pod, now time.Time) time.Duration {
	created := p.Metadata.CreationTimestamp
	if created == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return 0
	}
	if now.Before(t) {
		return 0
	}
	return now.Sub(t)
}

// controllerRef returns the owner reference marked as the managing controller,
// or nil if there is none.
func controllerRef(refs []OwnerReference) *OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	return nil
}

// workloadOwner resolves a pod to the workload a human acts on. The immediate
// controller is usually a ReplicaSet (for a Deployment), a Job, a DaemonSet, or
// a StatefulSet. A ReplicaSet is resolved one hop further to its Deployment via
// the ReplicaSet store, because "Deployment/foo" is what an operator recognizes,
// not the hashed ReplicaSet name.
func workloadOwner(p Pod, replicaSets *store[ReplicaSet]) string {
	ctrl := controllerRef(p.Metadata.OwnerReferences)
	if ctrl == nil {
		return ""
	}
	if ctrl.Kind == "ReplicaSet" && replicaSets != nil {
		if rs, ok := replicaSets.get(p.Metadata.Namespace + "/" + ctrl.Name); ok {
			if dep := controllerRef(rs.Metadata.OwnerReferences); dep != nil {
				return dep.Kind + "/" + dep.Name
			}
		}
		return "ReplicaSet/" + ctrl.Name
	}
	return ctrl.Kind + "/" + ctrl.Name
}

// nodeReady reports whether the node's Ready condition is True. It feeds the
// cluster "ready" count and ignores pressure and cordons.
func nodeReady(n Node) bool {
	for _, cond := range n.Status.Conditions {
		if cond.Type == "Ready" {
			return cond.Status == "True"
		}
	}
	return false
}

// jobHealth derives a Job's health: a Job with a Failed condition (typically
// backoffLimit exceeded, so it has already retried) is a real failure. Active,
// complete, and pending Jobs are healthy.
func jobHealth(j Job) healthState {
	for _, cond := range j.Status.Conditions {
		if cond.Type == "Failed" && cond.Status == "True" {
			msg := cond.Message
			if msg == "" {
				msg = cond.Reason
			}
			return healthState{false, "JobFailed", msg}
		}
	}
	return healthState{true, "", ""}
}

// jobFinished reports whether a Job has finished, and whether it failed.
func jobFinished(j Job) (finished, failed bool) {
	for _, c := range j.Status.Conditions {
		if c.Status != "True" {
			continue
		}
		switch c.Type {
		case "Failed":
			return true, true
		case "Complete":
			finished = true
		}
	}
	return finished, false
}

// supersededJobs returns the keys of failed Jobs that are not their owner's
// most recent finished run. A CronJob keeps failed runs as history
// (failedJobsHistoryLimit) after a later run succeeds; those Jobs describe the
// past, not the CronJob's current state. Jobs without an owner are never
// superseded.
func supersededJobs(jobs []Job) map[string]bool {
	type run struct {
		key, owner string
		when       time.Time
	}
	latest := map[string]time.Time{}
	var failed []run
	for _, j := range jobs {
		owner := jobOwner(j)
		done, didFail := jobFinished(j)
		if owner == "" || !done {
			continue
		}
		when, err := time.Parse(time.RFC3339, j.Metadata.CreationTimestamp)
		if err != nil {
			continue
		}
		owner = j.Metadata.Namespace + "|" + owner
		if when.After(latest[owner]) {
			latest[owner] = when
		}
		if didFail {
			failed = append(failed, run{key: j.key(), owner: owner, when: when})
		}
	}
	out := map[string]bool{}
	for _, r := range failed {
		if latest[r.owner].After(r.when) {
			out[r.key] = true
		}
	}
	return out
}

// jobOwner returns the Job's controller, usually the CronJob that created it, or
// an empty string when it has none.
func jobOwner(j Job) string {
	if ctrl := controllerRef(j.Metadata.OwnerReferences); ctrl != nil {
		return ctrl.Kind + "/" + ctrl.Name
	}
	return ""
}

// workloadState is the normalized availability view of a Deployment,
// StatefulSet or DaemonSet. Workload availability is the impact model: it
// answers "is anything degraded", which decides whether a human is notified.
type workloadState struct {
	kind      string // Deployment | StatefulSet | DaemonSet
	namespace string
	name      string
	desired   int
	available int
	updated   int
	// rollingOut is true while the controller has not yet converged on the
	// current spec. A deploy in progress legitimately depresses availability,
	// and on a busy cluster that accounts for most availability dips.
	rollingOut bool
}

func (w workloadState) key() string { return w.kind + "|" + w.namespace + "|" + w.name }

// ref is the "Kind/name" form an operator recognizes; see qualify for the
// namespace-qualified target.
func (w workloadState) ref() string { return w.kind + "/" + w.name }

// desiredReplicas resolves spec.replicas, where absent means 1 and an explicit
// 0 means deliberately scaled down.
func desiredReplicas(spec DeploymentSpec) int {
	if spec.Replicas == nil {
		return 1
	}
	return *spec.Replicas
}

func workloadStateOfDeployment(d Deployment) workloadState {
	desired := desiredReplicas(d.Spec)
	return workloadState{
		kind: "Deployment", namespace: d.Metadata.Namespace, name: d.Metadata.Name,
		desired: desired, available: d.Status.AvailableReplicas, updated: d.Status.UpdatedReplicas,
		rollingOut: isRollingOut(d.Metadata, d.Status.ObservedGeneration, d.Status.UpdatedReplicas, desired),
	}
}

func workloadStateOfStatefulSet(s StatefulSet) workloadState {
	desired := desiredReplicas(s.Spec)
	return workloadState{
		kind: "StatefulSet", namespace: s.Metadata.Namespace, name: s.Metadata.Name,
		desired: desired, available: s.Status.AvailableReplicas, updated: s.Status.UpdatedReplicas,
		rollingOut: isRollingOut(s.Metadata, s.Status.ObservedGeneration, s.Status.UpdatedReplicas, desired),
	}
}

func workloadStateOfDaemonSet(d DaemonSet) workloadState {
	desired := d.Status.DesiredNumberScheduled
	return workloadState{
		kind: "DaemonSet", namespace: d.Metadata.Namespace, name: d.Metadata.Name,
		desired: desired, available: d.Status.NumberAvailable, updated: d.Status.UpdatedNumberScheduled,
		rollingOut: isRollingOut(d.Metadata, d.Status.ObservedGeneration, d.Status.UpdatedNumberScheduled, desired),
	}
}

// isRollingOut reports whether the controller is still converging: either it has
// not yet observed the current spec generation, or it has not finished replacing
// pods with the updated template.
func isRollingOut(meta ObjectMeta, observedGeneration int64, updated, desired int) bool {
	if meta.Generation > 0 && observedGeneration < meta.Generation {
		return true
	}
	return desired > 0 && updated < desired
}

// workloadHealth derives the impact verdict for a workload.
//
// A workload scaled to zero is healthy by choice, and one mid-rollout is
// deploying rather than degraded. Otherwise available replicas are compared
// with desired ones.
//
// rolloutExpired bounds the rollout exemption: a wedged deploy (a bad image, an
// unschedulable template) would otherwise stay "rolling out" forever and its
// lost availability would never be reported. Past the grace period the dip
// counts like any other.
func workloadHealth(w workloadState, rolloutExpired bool) healthState {
	if w.desired == 0 {
		return healthState{true, "", ""} // deliberately scaled down
	}
	if w.available >= w.desired {
		return healthState{true, "", ""}
	}
	if w.rollingOut && !rolloutExpired {
		// Expected dip. Suppressed here rather than in the noise policy so the
		// reason never reaches a finding at all.
		return healthState{true, "", ""}
	}
	stalled := ""
	if w.rollingOut {
		stalled = " (rollout has not progressed)"
	}
	if w.available == 0 {
		return healthState{false, "Unavailable",
			fmt.Sprintf("no replicas available (0/%d)%s", w.desired, stalled)}
	}
	return healthState{false, "Degraded",
		fmt.Sprintf("%d of %d replicas available%s", w.available, w.desired, stalled)}
}

// pdbHealth reports whether a PDB is actually violated.
//
// The test is currentHealthy < desiredHealthy, not disruptionsAllowed == 0. A
// tight but correct PDB (minAvailable equal to the replica count, common for
// database StatefulSets) sits at zero allowed disruptions permanently and is
// healthy. A violation means the workload has dropped below what its owners
// declared they can tolerate.
func pdbHealth(p PodDisruptionBudget) healthState {
	if p.Status.DesiredHealthy == 0 {
		return healthState{true, "", ""}
	}
	if p.Status.CurrentHealthy < p.Status.DesiredHealthy {
		return healthState{false, "PDBViolated",
			fmt.Sprintf("%d healthy, %d required by the disruption budget",
				p.Status.CurrentHealthy, p.Status.DesiredHealthy)}
	}
	return healthState{true, "", ""}
}

// serviceEndpoints is the aggregate of every EndpointSlice for one Service.
type serviceEndpoints struct {
	namespace string
	name      string
	total     int
	ready     int
}

func (s serviceEndpoints) key() string { return "Service|" + s.namespace + "|" + s.name }

func (s serviceEndpoints) ref() string { return "Service/" + s.name }

// endpointsHealth flags a Service that has endpoints but none ready, so traffic
// has nowhere to land.
//
// A Service with no endpoints at all is not flagged: that is a workload scaled
// to zero or a Service with nothing registered yet, and flagging it would fire
// on every idle Service in the cluster.
func endpointsHealth(s serviceEndpoints) healthState {
	if s.total == 0 {
		return healthState{true, "", ""}
	}
	if s.ready == 0 {
		return healthState{false, "NoReadyEndpoints",
			fmt.Sprintf("none of %d endpoints are ready", s.total)}
	}
	return healthState{true, "", ""}
}

// aggregateEndpointSlices groups slices by their Service.
func aggregateEndpointSlices(slices []EndpointSlice) []serviceEndpoints {
	byService := map[string]*serviceEndpoints{}
	for _, sl := range slices {
		svc := sl.serviceName()
		if svc == "" {
			continue // not owned by a Service; nothing to reason about
		}
		k := sl.Metadata.Namespace + "/" + svc
		agg := byService[k]
		if agg == nil {
			agg = &serviceEndpoints{namespace: sl.Metadata.Namespace, name: svc}
			byService[k] = agg
		}
		for _, ep := range sl.Endpoints {
			agg.total++
			if ep.ready() {
				agg.ready++
			}
		}
	}
	out := make([]serviceEndpoints, 0, len(byService))
	for _, v := range byService {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].namespace != out[j].namespace {
			return out[i].namespace < out[j].namespace
		}
		return out[i].name < out[j].name
	})
	return out
}
