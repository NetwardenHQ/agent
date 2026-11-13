package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NetwardenHQ/agent/internal/dsm"
)

// On DSM the agent runs as the package user, which cannot create
// /var/lib/netwarden; its state belongs in the package's own data folder,
// where the config file is.
func TestDSMKeepsStateBesideTheConfig(t *testing.T) {
	dir := t.TempDir()
	old := dsm.Marker
	dsm.Marker = filepath.Join(dir, "synoinfo.conf")
	t.Cleanup(func() { dsm.Marker = old })
	if err := os.WriteFile(dsm.Marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "netwarden.conf")
	if err := os.WriteFile(path, []byte("tenant_id: abcdefghij\napi_key: nw_sk_test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SpoolDir != filepath.Join(dir, "spool") {
		t.Errorf("spool = %q", cfg.SpoolDir)
	}
	if cfg.FIMManifestPath != filepath.Join(dir, "fim-manifest") {
		t.Errorf("fim manifest = %q", cfg.FIMManifestPath)
	}

	// What the owner sets explicitly stays.
	body := "tenant_id: abcdefghij\napi_key: nw_sk_test\nspool_dir: /volume1/x/spool\nfim_manifest_path: /volume1/x/fim\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SpoolDir != "/volume1/x/spool" || cfg.FIMManifestPath != "/volume1/x/fim" {
		t.Errorf("explicit paths overridden: %q %q", cfg.SpoolDir, cfg.FIMManifestPath)
	}
}
