//go:build freebsd

package fim

// defaultManifestPath is the FIM baseline location on FreeBSD: /var/db is
// where hier(7) puts persistent daemon state (/var/lib does not exist there).
func defaultManifestPath() string { return "/var/db/netwarden/fim-manifest" }
