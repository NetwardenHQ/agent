//go:build !linux && !darwin && !windows && !freebsd

package fim

const rulesetRevision = 1

// defaultRoots is empty on platforms without a curated ruleset (anything but
// Linux, macOS, FreeBSD and Windows). FIM there watches only operator-configured
// roots (fim_roots).
func defaultRoots(Scope) []string { return nil }
