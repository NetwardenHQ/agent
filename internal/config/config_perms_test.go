//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig creates a minimally valid config file with the given mode.
func writeConfig(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netwarden.conf")
	body := "tenant_id: abcdefghij\napi_key: nw_sk_testkeyvalue\n"
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to umask; force the exact mode we are testing.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// A loose config file must not prevent the agent from starting — an existing
// fleet would go dark on upgrade. The check warns; it does not fail.
func TestLoadConfig_PermissiveModeStillLoads(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o666, 0o604} {
		cfg, err := LoadConfig(writeConfig(t, mode))
		if err != nil {
			t.Fatalf("mode %#o: LoadConfig failed: %v", mode, err)
		}
		if cfg.APIKey != "nw_sk_testkeyvalue" {
			t.Errorf("mode %#o: config not parsed, got APIKey %q", mode, cfg.APIKey)
		}
	}
}

func TestLoadConfig_SecureModeLoads(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if _, err := LoadConfig(writeConfig(t, mode)); err != nil {
			t.Errorf("mode %#o: LoadConfig failed: %v", mode, err)
		}
	}
}

// The mask is what decides whether a warning fires, so assert it directly.
func TestInsecureConfigModeMask(t *testing.T) {
	secure := []os.FileMode{0o600, 0o400, 0o700}
	insecure := []os.FileMode{0o640, 0o644, 0o604, 0o660, 0o666, 0o602, 0o620}

	for _, m := range secure {
		if m&insecureConfigModeMask != 0 {
			t.Errorf("mode %#o flagged insecure but is owner-only", m)
		}
	}
	for _, m := range insecure {
		if m&insecureConfigModeMask == 0 {
			t.Errorf("mode %#o not flagged; group/world bits are set", m)
		}
	}
}
