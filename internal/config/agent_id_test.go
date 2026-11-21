package config

import (
	"runtime"
	"testing"

	"github.com/NetwardenHQ/agent/internal/dsm"
)

func TestAgentIDFile(t *testing.T) {
	if got := loadBody(t, "agent_id_file: /data/netwarden/agent-id\n").AgentIDFile; got != "/data/netwarden/agent-id" {
		t.Errorf("agent_id_file not honoured: %q", got)
	}

	// A pod has no default: its filesystem does not outlive it. A path on a
	// persistent volume is the way to have an id there.
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if runtime.GOOS == "linux" {
		if got := loadBody(t, "").AgentIDFile; got != "" {
			t.Errorf("default in a pod = %q, want none", got)
		}
	}
	if got := loadBody(t, "agent_id_file: /data/agent-id\n").AgentIDFile; got != "/data/agent-id" {
		t.Errorf("agent_id_file ignored in a pod: %q", got)
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if runtime.GOOS == "linux" && !dsm.Is() {
		if got := loadBody(t, "").AgentIDFile; got != "/var/lib/netwarden/agent-id" {
			t.Errorf("default = %q, want /var/lib/netwarden/agent-id", got)
		}
	}
}
