package security

import "time"

// Language-package discovery.
//
// This finds packages installed by language package managers directly on the
// host (pip into site-packages, npm into node_modules), which dpkg and rpm do
// not see. Each entry joins the same installed-packages snapshot as OS
// packages, tagged with its language ecosystem, so the platform matches it
// against OSV instead of the distro advisory feeds.
//
// # Limits
//
// A filesystem walk is the one potentially unbounded thing this agent does,
// so every traversal is fenced by the caps below and by the collection
// context's deadline. The walker stops at the first limit it hits and reports
// a partial inventory; a partial SBOM is acceptable, saturating a host's I/O
// is not.
const (
	// maxLangPackages caps total language packages returned across all roots.
	// A large build host can carry tens of thousands of node_modules entries;
	// past a few thousand the marginal SBOM value is low and the payload cost
	// is not.
	maxLangPackages = 5000

	// maxDirEntries caps how many directory entries the walker will examine
	// per collection cycle, across every root. It is the backstop against a
	// pathological tree such as a deep node_modules.
	maxDirEntries = 200000

	// maxWalkDepth bounds recursion depth. Package manifests live shallow
	// relative to their root (node_modules/<pkg>/package.json, or one nesting
	// level for scoped packages), so a small depth captures them without
	// descending arbitrary project trees.
	maxWalkDepth = 6

	// maxManifestBytes caps how much of a manifest file is read. package.json
	// and METADATA are kilobytes; anything larger is not a real manifest.
	maxManifestBytes = 1 << 20 // 1 MiB

	// langWalkBudget is the wall-clock ceiling for the whole language walk,
	// independent of the collection context, so this collector cannot dominate
	// a cycle even if the context deadline is generous.
	langWalkBudget = 20 * time.Second
)

// walkStats tracks a single walk against its caps. Shared across roots so the
// caps are global, not per-root.
type walkStats struct {
	dirEntries int
	packages   int
	deadline   time.Time
}

// exhausted reports whether any global cap has been reached.
func (w *walkStats) exhausted() bool {
	if w.dirEntries >= maxDirEntries || w.packages >= maxLangPackages {
		return true
	}
	if !w.deadline.IsZero() && time.Now().After(w.deadline) {
		return true
	}
	return false
}
