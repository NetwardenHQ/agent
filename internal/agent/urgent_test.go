package agent

import "testing"

// A collector asks for an early report from its own goroutine; asking twice
// before the loop runs is one request, and asking never blocks.
func TestRequestReportNeverBlocks(t *testing.T) {
	a := &Agent{urgent: make(chan struct{}, 1)}
	a.requestReport()
	a.requestReport()
	if len(a.urgent) != 1 {
		t.Fatalf("%d pending requests", len(a.urgent))
	}
	<-a.urgent
	a.requestReport()
	if len(a.urgent) != 1 {
		t.Fatal("a request after the loop ran was lost")
	}
}
