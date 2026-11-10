//go:build race

package k8s

// raceEnabled reports that the race detector is on. It slows the code under
// test several times over, so time budgets are not asserted under it.
const raceEnabled = true
