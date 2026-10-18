package k8s

import (
	"strings"
	"time"
)

// This file decides which unhealthy states are worth alerting on. On a
// spot-heavy cluster every routine node reclaim produces a burst of transient
// states (the node goes NotReady, its pods evict and reschedule) that resolve
// on their own within a minute.
//
// The policy keeps two verdicts distinct everywhere downstream:
//   - health: is the object in a bad state? (drives dashboards and counts)
//   - surface: should that state open a finding or alert? (drives deltas)

// reasonClass groups failure reasons by how the policy treats them.
type reasonClass int

const (
	// classImmediate is a failure a reclaim never causes, surfaced at once. A
	// container that cannot pull, cannot start, crash-loops, or was OOM-killed
	// is broken regardless of what the nodes are doing.
	classImmediate reasonClass = iota
	// classReschedule is transient churn: a pod Pending, Unschedulable or
	// Evicted while the cluster places it elsewhere. Expected during a reclaim;
	// surfaced only if it persists.
	classReschedule
	// classNodeGraced is a node condition that is often a brief blip (a spot
	// interruption, a momentary partition). Surface only after it persists.
	classNodeGraced
	// classSuppressed is an intentional state that never surfaces on its own
	// (a cordon is an operator draining a node).
	classSuppressed
	// classImpact is service impact: a workload below its desired availability,
	// a violated disruption budget, a Service with nothing ready. It still has
	// to persist, since a brief dip while a pod restarts is not an incident.
	classImpact
)

var immediateReasons = map[string]bool{
	"CrashLoopBackOff":           true,
	"ImagePullBackOff":           true,
	"ErrImagePull":               true,
	"InvalidImageName":           true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"RunContainerError":          true,
	"OOMKilled":                  true,
	"Failed":                     true,
	"JobFailed":                  true,
}

var rescheduleReasons = map[string]bool{
	"Pending":       true,
	"Unschedulable": true,
	"Evicted":       true,
}

// impactReasons are the only reasons that describe a service being less
// available than it promises; every other reason describes an object.
var impactReasons = map[string]bool{
	"Unavailable":      true,
	"Degraded":         true,
	"PDBViolated":      true,
	"NoReadyEndpoints": true,
}

var nodeGracedReasons = map[string]bool{
	"NotReady":          true,
	"NodeStatusUnknown": true,
	"MemoryPressure":    true,
	"DiskPressure":      true,
	"PIDPressure":       true,
}

// classify maps a derived reason to its policy class. An Init: prefix is
// stripped first (a failing init container shares its container's class). An
// unrecognized reason fails safe and is surfaced.
func classify(reason string) reasonClass {
	if reason == "Cordoned" {
		return classSuppressed
	}
	base := strings.TrimPrefix(reason, "Init:")
	switch {
	case impactReasons[base]:
		return classImpact
	case immediateReasons[base]:
		return classImmediate
	case rescheduleReasons[base]:
		return classReschedule
	case nodeGracedReasons[base]:
		return classNodeGraced
	default:
		return classImmediate
	}
}

// noisePolicy holds the tunable windows.
type noisePolicy struct {
	// nodeGrace is how long a node condition must persist before it surfaces.
	nodeGrace time.Duration
	// rescheduleGrace is how long transient pod churn must persist (absent a
	// reclaim) before it surfaces.
	rescheduleGrace time.Duration
	// reclaimWindow is how long after a node reclaim transient pod churn is
	// treated as expected and fully suppressed.
	reclaimWindow time.Duration
	// rolloutGrace is how long a deploy may depress availability before the dip
	// counts as real impact. Without a bound, a wedged rollout would suppress
	// its own outage indefinitely.
	rolloutGrace time.Duration
	// sustainedFor is how long service impact must persist before it notifies.
	// It is shorter than the other graces because the impact is real, but not
	// zero, so a restart blip does not page.
	sustainedFor time.Duration
}

func defaultNoisePolicy() noisePolicy {
	return noisePolicy{
		nodeGrace:       2 * time.Minute,
		rescheduleGrace: 2 * time.Minute,
		reclaimWindow:   5 * time.Minute,
		rolloutGrace:    10 * time.Minute,
		sustainedFor:    90 * time.Second,
	}
}

// surface decides whether an unhealthy object should open a finding.
// unhealthyFor is how long it has been unhealthy; reclaimOpen is whether a node
// was reclaimed recently.
func (p noisePolicy) surface(reason string, unhealthyFor time.Duration, reclaimOpen bool) bool {
	switch classify(reason) {
	case classImmediate:
		return true
	case classSuppressed:
		return false
	case classReschedule:
		if reclaimOpen {
			return false // expected churn while the cluster reschedules
		}
		return unhealthyFor >= p.rescheduleGrace
	case classImpact:
		// Never suppressed by a reclaim: if availability is down, the cause
		// does not matter.
		return unhealthyFor >= p.sustainedFor
	case classNodeGraced:
		return unhealthyFor >= p.nodeGrace
	default:
		return true
	}
}
