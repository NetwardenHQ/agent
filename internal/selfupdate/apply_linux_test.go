//go:build linux

package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradeRequestIsWrittenWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-request")
	if err := writeUpgradeRequest(path, "3.3.0"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "3.3.0\n" {
		t.Fatalf("request = %q", got)
	}
	// Only the request itself is left: the temporary file was renamed into
	// place, which is what keeps the path unit from seeing a partial write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("left behind: %v", entries)
	}

	// A second request replaces the first.
	if err := writeUpgradeRequest(path, "3.3.1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "3.3.1\n" {
		t.Fatalf("request = %q", got)
	}
}

func TestUpgradeRequestFailsWithoutItsDirectory(t *testing.T) {
	if err := writeUpgradeRequest(filepath.Join(t.TempDir(), "missing", "update-request"), "3.3.0"); err == nil {
		t.Fatal("expected an error when the state directory does not exist")
	}
}
