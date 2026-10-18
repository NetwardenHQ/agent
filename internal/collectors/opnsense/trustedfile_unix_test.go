//go:build !windows

package opnsense

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFirmwareRefusesUntrustedFiles(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	os.WriteFile(real, []byte(`{"connection":"ok","repository":"ok"}`), 0o600)
	link := filepath.Join(dir, "link.json")
	os.Symlink(real, link)
	fifo := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose.json")
	os.WriteFile(loose, []byte(`{}`), 0o600)
	os.Chmod(loose, 0o666)
	me := uint32(os.Getuid())
	for name, c := range map[string]struct {
		path  string
		owner uint32
	}{"symlink": {link, me}, "fifo": {fifo, me}, "world-writable": {loose, me}, "wrong owner": {real, me + 1}} {
		if _, _, err := readTrustedFile(c.path, c.owner, 1<<20); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := readTrustedFile(real, me, 4); err == nil {
		t.Error("oversized file accepted")
	}
	if _, _, err := readTrustedFile(real, me, 1<<20); err != nil {
		t.Errorf("trusted file refused: %v", err)
	}
}
