package container

import (
	"testing"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

func TestParseStatus(t *testing.T) {
	cases := []struct {
		status  string
		health  string
		exit    int
		hasExit bool
	}{
		{"Up 5 seconds (healthy)", "healthy", 0, false},
		{"Up 2 minutes (health: starting)", "starting", 0, false},
		{"Up 3 hours (unhealthy)", "unhealthy", 0, false},
		{"Up 3 hours", "", 0, false},
		{"Exited (3) 5 seconds ago", "", 3, true},
		{"Exited (137) 2 hours ago", "", 137, true},
		{"Restarting (1) 4 seconds ago", "", 0, false},
		{"Created", "", 0, false},
	}
	for _, c := range cases {
		health, exit := parseStatus(c.status)
		if health != c.health {
			t.Errorf("%q: health = %q, want %q", c.status, health, c.health)
		}
		if (exit != nil) != c.hasExit || (exit != nil && *exit != c.exit) {
			t.Errorf("%q: exit code = %v, want %d (present %v)", c.status, exit, c.exit, c.hasExit)
		}
	}
}

func TestStateCode(t *testing.T) {
	for state, want := range map[string]float64{
		"running": stateRunning, "Running": stateRunning, "exited": stateExited, "stopped": stateExited,
		"restarting": stateRestarting, "paused": statePaused, "dead": stateDead, "created": stateCreated,
		"removing": stateRemoving, "something-new": stateUnknown,
	} {
		if got := stateCode(state); got != want {
			t.Errorf("stateCode(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestStateMetrics(t *testing.T) {
	c := &Collector{builder: metrics.NewBuilder().WithHostname("test")}
	three, five := 3, 5
	got := map[string]float64{}
	for _, m := range c.stateMetrics("abc123def456", Container{Status: "exited", ExitCode: &three, Restarts: &five}, nil) {
		got[m.Name] = m.Value
	}
	want := map[string]float64{
		"container_state_abc123def456":     stateExited,
		"container_exit_code_abc123def456": 3,
		"container_restarts_abc123def456":  5,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %v, want %v", name, got[name], v)
		}
	}

	got = map[string]float64{}
	for _, m := range c.stateMetrics("abc123def456", Container{Status: "running", Health: "unhealthy"}, nil) {
		got[m.Name] = m.Value
	}
	if got["container_health_abc123def456"] != healthUnhealthy || got["container_state_abc123def456"] != stateRunning {
		t.Errorf("running unhealthy container: got %v", got)
	}
	if _, ok := got["container_exit_code_abc123def456"]; ok {
		t.Error("a running container must not report an exit code")
	}
}
