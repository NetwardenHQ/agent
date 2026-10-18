package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every self_update option documented in the generated example config must
// be parsed: an operator who uncomments one expects it to take effect.
func TestExampleConfigParsesSelfUpdateOptions(t *testing.T) {
	example := filepath.Join(t.TempDir(), "example.conf")
	if err := CreateConfigFile(example); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(example)
	if err != nil {
		t.Fatal(err)
	}

	// Uncomment every self_update line and give the file credentials so it
	// loads, then confirm each value landed.
	var out []string
	seen := 0
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "# self_update"):
			out = append(out, strings.TrimPrefix(trimmed, "# "))
			seen++
		case strings.HasPrefix(trimmed, "tenant_id:"):
			out = append(out, "tenant_id: abcdefghij")
		case strings.HasPrefix(trimmed, "api_key:"):
			out = append(out, "api_key: nw_sk_test_key_value_1234567890")
		default:
			out = append(out, line)
		}
	}
	if seen != 5 {
		t.Fatalf("expected 5 documented self_update options, found %d", seen)
	}

	path := filepath.Join(t.TempDir(), "netwarden.conf")
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.SelfUpdate.Enabled {
		t.Error("self_update: true was not parsed")
	}
	if cfg.SelfUpdate.WindowStartHour != 1 || cfg.SelfUpdate.WindowEndHour != 5 {
		t.Errorf("window not parsed, got %d-%d",
			cfg.SelfUpdate.WindowStartHour, cfg.SelfUpdate.WindowEndHour)
	}
	if cfg.SelfUpdate.URLTemplate != "https://mirror.internal/netwarden-{version}-{os}-{arch}-installer.exe" {
		t.Errorf("self_update_url not parsed, got %q", cfg.SelfUpdate.URLTemplate)
	}
	if len(cfg.SelfUpdate.Signers) != 1 || cfg.SelfUpdate.Signers[0] != "Acme Corp" {
		t.Errorf("self_update_signers not parsed, got %v", cfg.SelfUpdate.Signers)
	}
}

// CreateConfigFile must never clobber a config that already holds credentials.
func TestCreateConfigFileRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netwarden.conf")
	original := "tenant_id: abcdefghij\napi_key: nw_sk_keep_me\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CreateConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected an already-exists error, got %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != original {
		t.Fatalf("existing config was modified: %q", got)
	}
}

// The documented default must be the real default.
func TestSelfUpdateDefaultsWithoutAnyOption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netwarden.conf")
	body := "tenant_id: abcdefghij\napi_key: nw_sk_test_key_value_1234567890\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SelfUpdate.Enabled {
		t.Error("self-update should be on by default")
	}
	if cfg.SelfUpdate.WindowStartHour != 1 || cfg.SelfUpdate.WindowEndHour != 5 {
		t.Errorf("default window should be 1-5, got %d-%d",
			cfg.SelfUpdate.WindowStartHour, cfg.SelfUpdate.WindowEndHour)
	}
	// No local override means the platform decides where to download from.
	if cfg.SelfUpdate.URLTemplate != "" {
		t.Errorf("no URL should be pinned by default, got %q", cfg.SelfUpdate.URLTemplate)
	}
	if len(cfg.SelfUpdate.Signers) != 0 {
		t.Errorf("no signer override by default, got %v", cfg.SelfUpdate.Signers)
	}
}
