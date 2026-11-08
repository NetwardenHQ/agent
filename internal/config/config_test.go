package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadBody(t *testing.T, extra string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netwarden.conf")
	body := "tenant_id: abcdefghij\napi_key: nw_sk_testkeyvalue\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestIngressLogsOffByDefault(t *testing.T) {
	// Reading the ingress log needs a RoleBinding the install manifest only
	// grants when asked, so a config without the key must not try.
	cfg := loadBody(t, "")
	if cfg.Collectors.K8sIngressLogs {
		t.Error("ingress logs on without k8s_enable_ingress_logs")
	}
	if cfg.K8sIngressLogsNamespace != "ingress-nginx" {
		t.Errorf("namespace %q", cfg.K8sIngressLogsNamespace)
	}

	cfg = loadBody(t, "k8s_enable_ingress_logs: true\nk8s_ingress_logs_namespace: edge-ingress\n")
	if !cfg.Collectors.K8sIngressLogs || cfg.K8sIngressLogsNamespace != "edge-ingress" {
		t.Errorf("on=%v namespace=%q", cfg.Collectors.K8sIngressLogs, cfg.K8sIngressLogsNamespace)
	}
	if cfg = loadBody(t, "k8s_ingress_logs_namespace: \n"); cfg.K8sIngressLogsNamespace != "ingress-nginx" {
		t.Errorf("an empty namespace must keep the default, got %q", cfg.K8sIngressLogsNamespace)
	}
}

func TestSpoolVolume(t *testing.T) {
	if cfg := loadBody(t, ""); cfg.SpoolVolume != "" {
		t.Errorf("spool volume %q by default", cfg.SpoolVolume)
	}
	cfg := loadBody(t, "spool_dir: /var/lib/netwarden/spool/agent\nspool_volume: /var/lib/netwarden/spool\n")
	if cfg.SpoolDir != "/var/lib/netwarden/spool/agent" || cfg.SpoolVolume != "/var/lib/netwarden/spool" {
		t.Errorf("dir %q volume %q", cfg.SpoolDir, cfg.SpoolVolume)
	}
}
