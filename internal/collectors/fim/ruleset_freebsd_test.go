//go:build freebsd

package fim

import (
	"slices"
	"testing"
)

// OPNsense rewrites /conf/config.xml on every save in its web UI, and its
// plugin reports configuration changes as events; only the full scope
// watches it.
func TestFreeBSDCredentialScope(t *testing.T) {
	creds, full := defaultRoots(ScopeCredentials), defaultRoots(ScopeFull)
	if slices.Contains(creds, "/conf/config.xml") || !slices.Contains(full, "/conf/config.xml") {
		t.Fatal("config.xml must be in the full scope only")
	}
	if slices.Contains(creds, "/usr/local/bin") || !slices.Contains(creds, "/etc/master.passwd") {
		t.Fatalf("credential scope %v", creds)
	}
}
