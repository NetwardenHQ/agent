//go:build linux || darwin

package fim

// defaultManifestPath is the FIM baseline location on Unix: a dedicated,
// root-owned state dir.
func defaultManifestPath() string { return "/var/lib/netwarden/fim-manifest" }
