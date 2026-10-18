//go:build linux || darwin || freebsd

package fim

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO swapped in for a regular file must not block the walk.
func TestFIFODoesNotHang(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	os.WriteFile(reg, []byte("x"), 0o644)
	info, _ := os.Lstat(reg)
	os.Remove(reg)
	if err := syscall.Mkfifo(reg, 0o644); err != nil {
		t.Skip(err)
	}
	done := make(chan struct{})
	go func() {
		recordFile(context.Background(), reg, info)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("hashing a FIFO blocked")
	}
}

// A symlink swapped in for a regular file is not followed.
func TestSymlinkSwapNotFollowed(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg")
	os.WriteFile(reg, []byte("x"), 0o644)
	info, _ := os.Lstat(reg)
	os.Remove(reg)
	os.Symlink("/dev/zero", reg)
	if _, ok := recordFile(context.Background(), reg, info); ok {
		t.Fatal("recorded a symlink swapped in after the listing")
	}
}

// Kernel pseudo-filesystems are never walked, even when named as a root.
func TestPseudoFSSkipped(t *testing.T) {
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("no /proc")
	}
	if n := len(buildEntries(context.Background(), []string{"/proc/self"}).entries); n != 0 {
		t.Fatalf("walked %d files under /proc", n)
	}
}
