//go:build freebsd

package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreeBSDSSHDConfigPath(t *testing.T) {
	touch := func(t *testing.T, root, rel string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		files []string
		want  string
	}{
		{"base sshd", []string{"etc/ssh/sshd_config"}, "etc/ssh/sshd_config"},
		{"port sshd", []string{"usr/local/sbin/sshd", "usr/local/etc/ssh/sshd_config", "etc/ssh/sshd_config"}, "usr/local/etc/ssh/sshd_config"},
		{"port config without port binary", []string{"usr/local/etc/ssh/sshd_config", "etc/ssh/sshd_config"}, "etc/ssh/sshd_config"},
		{"port binary without its config", []string{"usr/local/sbin/sshd", "etc/ssh/sshd_config"}, "etc/ssh/sshd_config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for _, f := range tt.files {
				touch(t, root, f)
			}
			if got, want := freebsdSSHDConfigPath(root), filepath.Join(root, tt.want); got != want {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}
