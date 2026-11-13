//go:build linux

package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NetwardenHQ/agent/internal/dsm"
)

// DSM has no /etc/os-release; its version is in /etc.defaults/VERSION.
func TestDistroOnDSM(t *testing.T) {
	dir := t.TempDir()
	oldM, oldV := dsm.Marker, dsm.VersionFile
	dsm.Marker, dsm.VersionFile = filepath.Join(dir, "synoinfo.conf"), filepath.Join(dir, "VERSION")
	t.Cleanup(func() { dsm.Marker, dsm.VersionFile = oldM, oldV })
	if err := os.WriteFile(dsm.Marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dsm.VersionFile, []byte("productversion=\"7.4.1\"\nbuildnumber=\"90080\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := readDistro(filepath.Join(dir, "no-os-release"))
	if err != nil {
		t.Fatalf("readDistro on DSM: %v", err)
	}
	if d.ID != "dsm" || d.VersionID != "7.4.1" {
		t.Errorf("distro = %+v", d)
	}
}
