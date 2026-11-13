package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTripwireKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netwarden.conf")
	body := "tenant_id: abcdefghij\napi_key: nw_sk_test\n" +
		"tripwire_canaries: /volume1/homes/alice/Documents/Passwords.xls@sha256:87d3dae8799db2c503d4e1064ce88613ce864b98b6a28263b234de6b0ea77ba6, /srv/Finance/Tax return 2025.pdf\n" +
		"tripwire_folders: /srv/share\n" +
		"tripwire_walk_minutes: 30\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TripwireCanaries) != 2 || cfg.TripwireCanaries[1] != "/srv/Finance/Tax return 2025.pdf" {
		t.Errorf("canaries = %q", cfg.TripwireCanaries)
	}
	if len(cfg.TripwireFolders) != 1 || cfg.TripwireWalkMinutes != 30 {
		t.Errorf("folders = %q, minutes = %d", cfg.TripwireFolders, cfg.TripwireWalkMinutes)
	}
	// The baseline sits beside the config: writable by the agent everywhere,
	// including the unprivileged Synology package.
	if cfg.TripwireStatePath != filepath.Join(dir, "tripwire.json") {
		t.Errorf("state path = %q", cfg.TripwireStatePath)
	}
}
