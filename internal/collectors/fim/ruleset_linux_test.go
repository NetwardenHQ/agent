//go:build linux

package fim

import (
	"slices"
	"testing"
)

var binaryDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}

func TestCredentialScopeExcludesBinaryDirs(t *testing.T) {
	roots := defaultRoots(ScopeCredentials)
	for _, dir := range binaryDirs {
		if slices.Contains(roots, dir) {
			t.Errorf("credential scope watches %s", dir)
		}
	}
	for _, want := range []string{"/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/pam.d", "/etc/ssh/sshd_config", "/etc/crontab"} {
		if !slices.Contains(roots, want) {
			t.Errorf("credential scope lacks %s", want)
		}
	}
}

func TestFullScopeIsTodaysList(t *testing.T) {
	want := []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"/etc/sudoers", "/etc/sudoers.d",
		"/etc/pam.d",
		"/etc/ssh/sshd_config",
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		"/etc/systemd/system",
		"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
		"/etc/cron.weekly", "/etc/cron.monthly", "/etc/crontab",
		"/etc/rc.local",
	}
	if got := defaultRoots(ScopeFull); !slices.Equal(got, want) {
		t.Fatalf("full scope changed:\n got %v\nwant %v", got, want)
	}
}

func TestCollectorDefaultsToCredentialScope(t *testing.T) {
	if got, want := NewCollector("h").roots, normalizeRoots(defaultRoots(ScopeCredentials)); !slices.Equal(got, want) {
		t.Fatalf("default roots %v, want %v", got, want)
	}
	if got, want := NewCollector("h", WithScope(ScopeFull)).roots, normalizeRoots(defaultRoots(ScopeFull)); !slices.Equal(got, want) {
		t.Fatalf("full roots %v, want %v", got, want)
	}
}
