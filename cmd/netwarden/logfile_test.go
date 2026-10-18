package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLogFileReopenFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netwarden.log")
	lf, err := openLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lf.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}
	// newsyslog renames the file, then signals the daemon.
	if err := os.Rename(path, path+".0"); err != nil {
		t.Fatal(err)
	}
	if err := lf.Reopen(); err != nil {
		t.Fatal(err)
	}
	if _, err := lf.Write([]byte("after\n")); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(path + ".0")
	cur, _ := os.ReadFile(path)
	if string(old) != "before\n" || string(cur) != "after\n" {
		t.Fatalf("rotated=%q current=%q", old, cur)
	}
}

// A symlink planted at the log path must not be followed: the agent runs as
// root and would otherwise append to whatever the link points at.
func TestLogFileRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no O_NOFOLLOW on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "netwarden.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if lf, err := openLogFile(path); err == nil {
		lf.f.Close()
		t.Fatal("openLogFile followed a symlink")
	}
	if got, _ := os.ReadFile(target); string(got) != "keep\n" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

// Reopen applies the same rule: a link swapped in after rotation is refused
// and logging continues on the current handle.
func TestLogFileReopenRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no O_NOFOLLOW on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "netwarden.log")
	lf, err := openLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".0"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := lf.Reopen(); err == nil {
		t.Fatal("Reopen followed a symlink")
	}
	if _, err := lf.Write([]byte("still here\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); len(got) != 0 {
		t.Fatalf("symlink target was written: %q", got)
	}
	if got, _ := os.ReadFile(path + ".0"); string(got) != "still here\n" {
		t.Fatalf("current handle lost the write: %q", got)
	}
}

// A new log file is not world-readable.
func TestLogFileCreatedWithoutWorldRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are synthesized on Windows")
	}
	path := filepath.Join(t.TempDir(), "netwarden.log")
	lf, err := openLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.f.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o007 != 0 {
		t.Fatalf("log file mode %#o grants world access", fi.Mode().Perm())
	}
}
