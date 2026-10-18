package agent

// snapshotAcker is implemented by collectors whose snapshot carries state that
// must not be lost to a failed post, such as FIM's detected changes. They keep
// offering the snapshot until told it was delivered.
type snapshotAcker interface {
	AckSnapshots()
}

// ackSnapshots tells every such collector that the snapshots drained for this
// cycle reached the platform. Call it only after the post that carried them
// returned 2xx.
func (a *Agent) ackSnapshots() {
	for _, name := range a.registry.ListCollectors() {
		if c, ok := a.registry.GetCollector(name).(snapshotAcker); ok {
			c.AckSnapshots()
		}
	}
}
