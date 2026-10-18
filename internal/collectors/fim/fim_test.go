package fim

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func e(path, hash, mode string, uid, gid uint32) Entry {
	return Entry{Path: path, Hash: hash, Mode: mode, UID: ptr(uid), GID: ptr(gid)}
}

func coversAll(string) bool { return true }

func changeFor(cs []Change, path string) (Change, bool) {
	for _, c := range cs {
		if c.Path == path {
			return c, true
		}
	}
	return Change{}, false
}

func TestDiff_DetectsEachKind(t *testing.T) {
	base := map[string]Entry{
		"/a": e("/a", "sha256:1", "0644", 0, 0), // will be modified
		"/b": e("/b", "sha256:2", "0644", 0, 0), // will change mode only
		"/c": e("/c", "sha256:3", "0644", 0, 0), // will be deleted
		"/d": e("/d", "sha256:4", "0644", 0, 0), // unchanged
	}
	cur := map[string]Entry{
		"/a": e("/a", "sha256:1x", "0644", 0, 0), // modified (hash differs)
		"/b": e("/b", "sha256:2", "0666", 0, 0),  // attr (mode loosened)
		"/d": e("/d", "sha256:4", "0644", 0, 0),  // unchanged
		"/e": e("/e", "sha256:5", "0600", 0, 0),  // created
	}

	changes := diff(base, cur, coversAll)

	if c, ok := changeFor(changes, "/a"); !ok || c.Change != ChangeModified || c.WasHash != "sha256:1" {
		t.Errorf("/a: %+v", c)
	}
	if c, ok := changeFor(changes, "/b"); !ok || c.Change != ChangeAttr {
		t.Errorf("/b should be attr change: %+v", c)
	}
	if c, ok := changeFor(changes, "/c"); !ok || c.Change != ChangeDeleted {
		t.Errorf("/c should be deleted: %+v", c)
	}
	if _, ok := changeFor(changes, "/d"); ok {
		t.Error("/d unchanged should not appear")
	}
	if c, ok := changeFor(changes, "/e"); !ok || c.Change != ChangeCreated {
		t.Errorf("/e should be created: %+v", c)
	}
}

// Identical content with a loosened mode is reported as an attr change.
func TestDiff_AttrOnlyChangeCaught(t *testing.T) {
	base := map[string]Entry{"/etc/shadow": e("/etc/shadow", "sha256:h", "0000", 0, 0)}
	cur := map[string]Entry{"/etc/shadow": e("/etc/shadow", "sha256:h", "0644", 0, 0)}
	changes := diff(base, cur, coversAll)
	if len(changes) != 1 || changes[0].Change != ChangeAttr {
		t.Fatalf("mode loosening on shadow must be an attr change, got %+v", changes)
	}
}

func TestRollupDigest_OrderIndependentAndSensitive(t *testing.T) {
	a := map[string]Entry{"/x": e("/x", "sha256:1", "0644", 0, 0), "/y": e("/y", "sha256:2", "0644", 0, 0)}
	b := map[string]Entry{"/y": e("/y", "sha256:2", "0644", 0, 0), "/x": e("/x", "sha256:1", "0644", 0, 0)}
	if rollupDigest(a) != rollupDigest(b) {
		t.Error("digest must be independent of map iteration order")
	}
	// A single mode change must move the digest.
	c := map[string]Entry{"/x": e("/x", "sha256:1", "0666", 0, 0), "/y": e("/y", "sha256:2", "0644", 0, 0)}
	if rollupDigest(a) == rollupDigest(c) {
		t.Error("digest must change when a file's mode changes")
	}
}

func TestNormalizeRoots(t *testing.T) {
	got := normalizeRoots([]string{"/usr/bin", "relative/path", "", "/usr/bin", "/etc/../etc/ssh"})
	want := map[string]bool{"/usr/bin": true, "/etc/ssh": true}
	if len(got) != 2 {
		t.Fatalf("expected 2 roots, got %v", got)
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("unexpected root %q", r)
		}
	}
}

func TestManifest_AtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "fim-manifest")
	m := &Manifest{ID: "abc", RulesetRev: 1, Entries: map[string]Entry{
		"/a": e("/a", "sha256:1", "0644", 0, 0),
	}}
	if err := saveManifest(path, m); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != manifestMode {
		t.Errorf("manifest mode = %o, want %o", info.Mode().Perm(), manifestMode)
	}
	loaded, insecure, err := loadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if insecure {
		t.Error("0600 manifest should not be flagged insecure")
	}
	if loaded.ID != "abc" || loaded.Entries["/a"].Hash != "sha256:1" {
		t.Errorf("round-trip lost data: %+v", loaded)
	}
}

func TestManifest_MissingIsNoBaseline(t *testing.T) {
	m, _, err := loadManifest(filepath.Join(t.TempDir(), "absent"))
	if err != nil || m != nil {
		t.Errorf("missing manifest should be (nil, nil), got (%v, %v)", m, err)
	}
}

func TestManifest_LoosePermsFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "fim-manifest")
	saveManifest(path, &Manifest{ID: "x", Entries: map[string]Entry{}})
	os.Chmod(path, 0o644) // group/world readable
	_, insecure, err := loadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if !insecure {
		t.Error("0644 manifest should be flagged insecure")
	}
}

func TestManifest_CorruptIsNoBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "fim-manifest")
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("{not json"), 0o600)
	m, _, err := loadManifest(path)
	if m != nil || err == nil || errors.Is(err, errManifestUntrusted) {
		t.Error("corrupt manifest should return an error and no baseline (rebuild)")
	}
}

func TestBuildEntries_HashesFilesAndBoundsSymlinks(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "bin1"), []byte("hello"), 0o755)
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "sub", "bin2"), []byte("world"), 0o644)

	// Symlinked dir out of tree must not be followed.
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o644)
	os.Symlink(outside, filepath.Join(root, "link"))

	entries := buildEntries(context.Background(), []string{root}).entries

	if _, ok := entries[filepath.Join(root, "bin1")]; !ok {
		t.Error("bin1 not recorded")
	}
	if _, ok := entries[filepath.Join(root, "sub", "bin2")]; !ok {
		t.Error("nested bin2 not recorded")
	}
	if _, ok := entries[filepath.Join(outside, "secret")]; ok {
		t.Error("walker followed a symlink out of the root")
	}
	got := entries[filepath.Join(root, "bin1")]
	if got.Hash == "" || got.Hash[:7] != "sha256:" {
		t.Errorf("bad hash: %q", got.Hash)
	}
	if got.Mode != "0755" {
		t.Errorf("mode = %q, want 0755", got.Mode)
	}
}

func TestBuildEntries_SingleFileRoot(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "sudoers")
	os.WriteFile(f, []byte("root ALL=(ALL) ALL"), 0o440)
	entries := buildEntries(context.Background(), []string{f}).entries
	if _, ok := entries[f]; !ok {
		t.Error("a file given directly as a root should be recorded")
	}
}
