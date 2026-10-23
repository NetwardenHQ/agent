package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// writeTarGz builds a release-shaped archive from name/content pairs.
func writeTarGz(t *testing.T, path string, files map[string]string, extra ...*tar.Header) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range extra {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractBinaryTakesTheNamedFile(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "release.tar.gz")
	writeTarGz(t, archive, map[string]string{"netwarden": "new agent", "README": "docs"})

	dst := filepath.Join(dir, "staged")
	if err := extractBinary(archive, "netwarden", dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new agent" {
		t.Fatalf("extracted %q", got)
	}
	fi, _ := os.Stat(dst)
	if fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("binary is not executable: %v", fi.Mode())
	}
}

func TestExtractBinaryIgnoresLookalikes(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "release.tar.gz")
	// A symlink called netwarden must not be followed or taken; neither may a
	// file of the same name in another directory.
	writeTarGz(t, archive, map[string]string{"bin/netwarden": "elsewhere"},
		&tar.Header{Name: "netwarden", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	if err := extractBinary(archive, "netwarden", filepath.Join(dir, "staged")); err == nil {
		t.Fatal("an archive without a regular netwarden file was accepted")
	}
}
