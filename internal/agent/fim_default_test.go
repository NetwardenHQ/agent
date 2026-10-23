package agent

import "testing"

// FIM is on by default for hosts; an agent inside a Kubernetes cluster would
// only be watching its own container image, so there it runs only when
// enable_fim says so.
func TestFIMWanted(t *testing.T) {
	cases := []struct{ enabled, explicit, inCluster, want bool }{
		{true, false, false, true},
		{true, false, true, false},
		{true, true, true, true},
		{false, true, false, false},
	}
	for _, c := range cases {
		if got := fimWanted(c.enabled, c.explicit, c.inCluster); got != c.want {
			t.Errorf("fimWanted(%v, %v, %v) = %v", c.enabled, c.explicit, c.inCluster, got)
		}
	}
}
