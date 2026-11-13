package dsm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAndVersion(t *testing.T) {
	dir := t.TempDir()
	Marker = filepath.Join(dir, "synoinfo.conf")
	VersionFile = filepath.Join(dir, "VERSION")
	if Is() {
		t.Fatal("DSM without its marker")
	}
	if err := os.WriteFile(Marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(VersionFile, []byte("majorversion=\"7\"\nproductversion=\"7.4.1\"\nbuildnumber=\"90080\"\nsmallfixnumber=\"1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Is() {
		t.Fatal("not DSM with the marker present")
	}
	if v, b := Version(); v != "7.4.1" || b != "90080" {
		t.Errorf("Version() = %q %q", v, b)
	}
}
