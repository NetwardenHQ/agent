package k8s

import "testing"

// Capabilities default to on, so a netwarden.conf without these keys keeps
// collecting everything.
func TestCapabilitiesDefaultToOn(t *testing.T) {
	c := NewCollector("prod-cluster")
	if !c.capJobs || !c.capAvailability || !c.capResources || !c.capCNPG || !c.capIngress {
		t.Fatalf("defaults off: jobs=%v availability=%v resources=%v cnpg=%v ingress=%v",
			c.capJobs, c.capAvailability, c.capResources, c.capCNPG, c.capIngress)
	}
}

func TestWithCapabilitiesTurnsThingsOff(t *testing.T) {
	c := NewCollector("prod-cluster", WithCapabilities(Capabilities{}))
	if c.capJobs || c.capAvailability || c.capResources || c.capCNPG || c.capIngress {
		t.Fatal("WithCapabilities(all false) left something enabled")
	}
}

// With usage collection disabled, an empty snapshot emits no usage series
// rather than zeros.
func TestNoUsageSeriesWhenResourcesDisabled(t *testing.T) {
	c := NewCollector("prod-cluster", WithCapabilities(Capabilities{Jobs: true, Availability: true}))
	if got := c.emitUsage(usageSnapshot{Available: false}, nowForTest()); len(got) != 0 {
		t.Fatalf("emitted %d usage series with the capability disabled", len(got))
	}
}
