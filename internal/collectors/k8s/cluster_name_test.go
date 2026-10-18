package k8s

import "testing"

// The server keys clusters on tenant and cluster name, so the name must never be
// empty. The install manifest sets the agent hostname to the cluster name,
// which makes the hostname the default.
func TestClusterNameDefaultsToHostname(t *testing.T) {
	if got := NewCollector("prod-cluster").clusterName; got != "prod-cluster" {
		t.Fatalf("clusterName = %q, want %q", got, "prod-cluster")
	}
}

func TestWithClusterNameOverrides(t *testing.T) {
	if got := NewCollector("prod-cluster", WithClusterName("prod-eu")).clusterName; got != "prod-eu" {
		t.Fatalf("clusterName = %q, want %q", got, "prod-eu")
	}
}
