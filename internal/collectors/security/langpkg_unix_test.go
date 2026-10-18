//go:build linux

package security

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// writeFile creates a file with parents.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasPkg(pkgs []installedPackage, eco, name, version string) bool {
	for _, p := range pkgs {
		if p.Ecosystem == eco && p.Name == name && p.Version == version {
			return true
		}
	}
	return false
}

func TestReadNodePackage(t *testing.T) {
	dir := t.TempDir()
	pj := filepath.Join(dir, "package.json")
	writeFile(t, pj, `{"name":"express","version":"4.18.2","dependencies":{"x":"1"}}`)

	p, ok := readNodePackage(pj)
	if !ok {
		t.Fatal("expected a package")
	}
	if p.Name != "express" || p.Version != "4.18.2" || p.Ecosystem != EcosystemNPM {
		t.Errorf("bad package: %+v", p)
	}
}

func TestReadNodePackage_Rejects(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{
		`{"version":"1.0.0"}`, // no name
		`{"name":"x"}`,        // no version
		`not json`,            // garbage
		`{}`,                  // empty
	} {
		pj := filepath.Join(dir, "package.json")
		writeFile(t, pj, bad)
		if _, ok := readNodePackage(pj); ok {
			t.Errorf("should have rejected: %s", bad)
		}
	}
}

func TestReadPythonMetadata(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "METADATA")
	// Real dist-info METADATA header, with a body after the blank line.
	writeFile(t, md, "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: HTTP\n\nLong README body\nName: not-a-real-field\n")

	p, ok := readPythonMetadata(md)
	if !ok {
		t.Fatal("expected a package")
	}
	if p.Name != "requests" || p.Version != "2.31.0" || p.Ecosystem != EcosystemPyPI {
		t.Errorf("bad package: %+v", p)
	}
}

func TestReadPythonMetadata_StopsAtBlankLine(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "METADATA")
	// A version that appears only in the body is not picked up.
	writeFile(t, md, "Name: foo\n\nVersion: 9.9.9\n")
	if _, ok := readPythonMetadata(md); ok {
		t.Error("version in body should not be read (header ended at blank line)")
	}
}

func TestScanRoot_NodeModules(t *testing.T) {
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	writeFile(t, filepath.Join(nm, "express", "package.json"), `{"name":"express","version":"4.18.2"}`)
	writeFile(t, filepath.Join(nm, "lodash", "package.json"), `{"name":"lodash","version":"4.17.21"}`)
	// Scoped package.
	writeFile(t, filepath.Join(nm, "@types", "node", "package.json"), `{"name":"@types/node","version":"20.0.0"}`)
	// Nested node_modules are not recursed into.
	writeFile(t, filepath.Join(nm, "express", "node_modules", "deep", "package.json"), `{"name":"deep","version":"1.0.0"}`)

	stats := &walkStats{}
	pkgs := scanRoot(context.Background(), root, stats)

	if !hasPkg(pkgs, EcosystemNPM, "express", "4.18.2") {
		t.Error("express not found")
	}
	if !hasPkg(pkgs, EcosystemNPM, "@types/node", "20.0.0") {
		t.Error("scoped package not found")
	}
	if hasPkg(pkgs, EcosystemNPM, "deep", "1.0.0") {
		t.Error("nested node_modules should NOT be recursed into")
	}
}

func TestScanRoot_PythonDistInfo(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "requests-2.31.0.dist-info", "METADATA"),
		"Name: requests\nVersion: 2.31.0\n")
	writeFile(t, filepath.Join(root, "legacy.egg-info", "PKG-INFO"),
		"Name: legacy\nVersion: 0.1.0\n")

	pkgs := scanRoot(context.Background(), root, &walkStats{})
	if !hasPkg(pkgs, EcosystemPyPI, "requests", "2.31.0") {
		t.Error("dist-info package not found")
	}
	if !hasPkg(pkgs, EcosystemPyPI, "legacy", "0.1.0") {
		t.Error("egg-info package not found")
	}
}

// A symlinked directory is never followed.
func TestScanRoot_DoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "node_modules", "secret", "package.json"),
		`{"name":"secret","version":"1.0.0"}`)

	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("symlink not supported")
	}
	pkgs := scanRoot(context.Background(), root, &walkStats{})
	if hasPkg(pkgs, EcosystemNPM, "secret", "1.0.0") {
		t.Error("walker followed a symlink out of the root")
	}
}

// The dirEntries cap must halt the walk.
func TestScanRoot_RespectsDirEntryCap(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 50; i++ {
		writeFile(t, filepath.Join(root, "node_modules",
			"pkg"+string(rune('a'+i%26))+string(rune('a'+i/26)), "package.json"),
			`{"name":"p","version":"1.0.0"}`)
	}
	// Start already at the cap: the walk should do essentially nothing.
	stats := &walkStats{dirEntries: maxDirEntries}
	pkgs := scanRoot(context.Background(), root, stats)
	if len(pkgs) != 0 {
		t.Errorf("expected no packages once dir-entry cap is hit, got %d", len(pkgs))
	}
}

// A cancelled context stops the walk promptly.
func TestScanRoot_RespectsContext(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "x", "package.json"), `{"name":"x","version":"1"}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pkgs := scanRoot(ctx, root, &walkStats{})
	if len(pkgs) != 0 {
		t.Errorf("cancelled context should yield no packages, got %d", len(pkgs))
	}
}

func TestCollectLanguagePackages_Dedupes(t *testing.T) {
	root := t.TempDir()
	// Same package under two roots -> one entry.
	writeFile(t, filepath.Join(root, "a", "node_modules", "x", "package.json"), `{"name":"x","version":"1.0.0"}`)
	writeFile(t, filepath.Join(root, "b", "node_modules", "x", "package.json"), `{"name":"x","version":"1.0.0"}`)

	pkgs, _ := collectLanguagePackages(context.Background(),
		[]string{filepath.Join(root, "a"), filepath.Join(root, "b")})

	n := 0
	for _, p := range pkgs {
		if p.Name == "x" && p.Version == "1.0.0" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected 1 deduplicated entry, got %d", n)
	}
}

func TestDiscoverPythonSiteDirs_Bounded(t *testing.T) {
	// Only real directories are returned.
	for _, d := range discoverPythonSiteDirs() {
		info, err := os.Stat(d)
		if err != nil || !info.IsDir() {
			t.Errorf("discovered non-directory: %s", d)
		}
	}
}

// A symlinked manifest is not read: it could point anywhere on the host.
func TestReadManifest_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.json")
	writeFile(t, target, `{"name":"evil","version":"6.6.6"}`)
	link := filepath.Join(dir, "package.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink not supported")
	}
	if _, ok := readNodePackage(link); ok {
		t.Error("readNodePackage followed a symlinked package.json")
	}
	mdLink := filepath.Join(dir, "METADATA")
	writeFile(t, target, "Name: evil\nVersion: 6.6.6\n")
	if err := os.Symlink(target, mdLink); err != nil {
		t.Fatal(err)
	}
	if _, ok := readPythonMetadata(mdLink); ok {
		t.Error("readPythonMetadata followed a symlinked METADATA")
	}
}

// A FIFO planted as a manifest is rejected without blocking.
func TestReadManifest_RejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "package.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo not supported")
	}
	done := make(chan bool, 1)
	go func() {
		_, ok := readNodePackage(fifo)
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Error("FIFO accepted as a manifest")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readNodePackage blocked on a FIFO")
	}
}

// Hitting a walk cap is reported as truncation.
func TestCollectLanguagePackages_ReportsTruncation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "x", "package.json"), `{"name":"x","version":"1.0.0"}`)
	if _, truncated := collectLanguagePackages(context.Background(), []string{root}); truncated {
		t.Error("small walk reported as truncated")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, truncated := collectLanguagePackages(ctx, []string{root}); !truncated {
		t.Error("cancelled walk not reported as truncated")
	}
}
