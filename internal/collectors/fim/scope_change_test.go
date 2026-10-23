package fim

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Switching scope changes the watched roots. The baseline must be rebuilt
// quietly (rebuild_reason "roots_changed", nothing reported as changed), not
// diffed into a delete for every file the new scope no longer watches.
func TestScopeChangeRebuildsBenignly(t *testing.T) {
	dir := t.TempDir()
	bins := filepath.Join(dir, "bin")
	creds := filepath.Join(dir, "etc")
	for _, d := range []string{bins, creds} {
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o644)
	}
	manifest := filepath.Join(dir, "state", "fim-manifest")

	full := NewCollector("host", WithManifestPath(manifest), WithInterval(time.Nanosecond))
	full.roots = normalizeRoots([]string{bins, creds}) // test only: the "full" ruleset
	full.Collect(context.Background())
	drain(full)

	narrow := NewCollector("host", WithManifestPath(manifest), WithInterval(time.Nanosecond))
	narrow.roots = normalizeRoots([]string{creds}) // test only: the credential ruleset
	narrow.Collect(context.Background())
	p := drain(narrow)[0].Payload
	if p["baseline_rebuilt"] != true || p["rebuild_reason"] != "roots_changed" {
		t.Fatalf("rebuilt %v, reason %v", p["baseline_rebuilt"], p["rebuild_reason"])
	}
	if changes, _ := p["changes"].([]map[string]any); len(changes) != 0 {
		t.Fatalf("a scope change reported %d file changes", len(changes))
	}
}
