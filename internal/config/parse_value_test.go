package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseValue(t *testing.T) {
	for raw, want := range map[string]string{
		" info":                                "info",
		" info     # debug, info, warn, error": "info",
		" eth0,eth1\t# only these":             "eth0,eth1",
		" abc#def":                             "abc#def", // '#' inside a value
		` "pa ss #word"  # quoted`:             "pa ss #word",
		` 'it''s'`:                             "it",
		` "unterminated # note`:                `"unterminated`,
		" ":                                    "",
	} {
		if got := parseValue(raw); got != want {
			t.Errorf("parseValue(%q) = %q, want %q", raw, got, want)
		}
	}
}

// Example lines with a note after the value must still configure the agent.
func TestLoadConfigIgnoresTrailingComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netwarden.conf")
	body := "tenant_id: abcdefghij     # Your 10-character tenant ID\n" +
		"api_key: nw_sk_testkeyvalue  # Your API key\n" +
		"log_level: warn                    # debug, info, warn, error\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TenantID != "abcdefghij" || cfg.APIKey != "nw_sk_testkeyvalue" || cfg.LogLevel != "warn" {
		t.Fatalf("got tenant %q key %q level %q", cfg.TenantID, cfg.APIKey, cfg.LogLevel)
	}
}
