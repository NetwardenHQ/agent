package tripwire

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestPlantCanaries(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Finance")
	planted, err := PlantCanaries(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(planted) != 4 {
		t.Fatalf("planted %d", len(planted))
	}
	for _, p := range planted {
		head, err := readHead(p.Path)
		if err != nil {
			t.Fatal(err)
		}
		// Each decoy is a valid file of its type, so it passes as real and
		// never trips the content checks itself.
		if why := suspicious(p.Path, head); why != "" {
			t.Errorf("%s: %s", filepath.Base(p.Path), why)
		}
		sum, _, err := fileHash(p.Path)
		if err != nil || sum != p.SHA256 {
			t.Errorf("%s: hash %s, reported %s (%v)", p.Path, sum, p.SHA256, err)
		}
		if p.Config() != p.Path+"@sha256:"+p.SHA256 {
			t.Errorf("config entry %q", p.Config())
		}
	}
	// The .docx opens as a zip with a document in it.
	for _, p := range planted {
		if filepath.Ext(p.Path) == ".docx" {
			r, err := zip.OpenReader(p.Path)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.File) < 3 {
				t.Errorf("docx has %d parts", len(r.File))
			}
			r.Close()
		}
	}
	// Planting never overwrites.
	if _, err := PlantCanaries(dir); err == nil {
		t.Error("planting over existing canaries succeeded")
	}
	// Two plantings differ, so a fixed decoy cannot be fingerprinted.
	other, err := PlantCanaries(filepath.Join(t.TempDir(), "x"))
	if err != nil {
		t.Fatal(err)
	}
	if other[0].SHA256 == planted[0].SHA256 {
		t.Error("two plantings produced identical decoys")
	}
	info, _ := os.Stat(planted[0].Path)
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
}
