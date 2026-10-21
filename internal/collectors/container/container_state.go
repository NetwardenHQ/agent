package container

import (
	"regexp"
	"strconv"
	"strings"
)

// Values of the container_state_<id> gauge. The platform reads these numbers,
// so they are part of the wire format: add new states at the end, never
// renumber.
const (
	stateUnknown    = -1
	stateCreated    = 0
	stateRunning    = 1
	statePaused     = 2
	stateRestarting = 3
	stateExited     = 4
	stateDead       = 5
	stateRemoving   = 6
)

// Values of the container_health_<id> gauge. Containers without a health
// check report no health series at all.
const (
	healthUnhealthy = 0
	healthHealthy   = 1
	healthStarting  = 2
)

// stateCode maps a runtime state ("running", "exited", ...) to its gauge value.
func stateCode(state string) float64 {
	switch strings.ToLower(state) {
	case "created", "configured", "initialized":
		return stateCreated
	case "running":
		return stateRunning
	case "paused":
		return statePaused
	case "restarting":
		return stateRestarting
	case "exited", "stopped":
		return stateExited
	case "dead":
		return stateDead
	case "removing":
		return stateRemoving
	default:
		return stateUnknown
	}
}

var (
	exitCodeRe = regexp.MustCompile(`^Exited \((-?\d+)\)`)
	healthRe   = regexp.MustCompile(`\((healthy|unhealthy|health: starting)\)`)
)

// parseStatus reads what the runtimes put in the human-readable Status column,
// which Docker's list endpoint offers instead of separate fields:
//
//	Up 3 hours (healthy)
//	Up 12 seconds (health: starting)
//	Exited (137) 2 hours ago
//	Restarting (1) 4 seconds ago
//
// health is "" when the container has no health check.
func parseStatus(status string) (health string, exitCode *int) {
	if m := healthRe.FindStringSubmatch(status); m != nil {
		health = strings.TrimPrefix(m[1], "health: ")
	}
	if m := exitCodeRe.FindStringSubmatch(status); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			exitCode = &n
		}
	}
	return health, exitCode
}

// healthCode maps a health check state to its gauge value; ok is false for a
// container with no health check.
func healthCode(health string) (value float64, ok bool) {
	switch health {
	case "healthy":
		return healthHealthy, true
	case "unhealthy":
		return healthUnhealthy, true
	case "starting":
		return healthStarting, true
	default:
		return 0, false
	}
}
