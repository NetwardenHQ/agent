package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnableFIMParsing(t *testing.T) {
	cases := []struct {
		line          string
		fim, explicit bool
		scope         string
	}{
		{"", true, false, "credentials"},
		{"enable_fim: true\n", true, true, "full"},
		{"enable_fim: false\n", false, true, "credentials"},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "netwarden.conf")
		body := "tenant_id: abcdefghij\napi_key: nw_sk_testkeyvalue\n" + c.line
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Collectors.FIM != c.fim || cfg.FIMExplicit != c.explicit || cfg.FIMScope != c.scope {
			t.Errorf("%q: FIM %v explicit %v scope %q", c.line, cfg.Collectors.FIM, cfg.FIMExplicit, cfg.FIMScope)
		}
	}
}
