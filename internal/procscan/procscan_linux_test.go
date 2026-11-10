//go:build linux

package procscan

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeProc builds a /proc with one entry per process: pid -> {name, namespace}.
func fakeProc(t *testing.T, ownNS string, procs map[string][2]string) string {
	t.Helper()
	root := t.TempDir()
	add := func(pid, comm, ns string) {
		dir := filepath.Join(root, pid, "ns")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if comm != "" {
			if err := os.WriteFile(filepath.Join(root, pid, "comm"), []byte(comm+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if ns != "" {
			if err := os.Symlink(ns, filepath.Join(dir, "pid")); err != nil {
				t.Fatal(err)
			}
		}
	}
	add("self", "", ownNS)
	for pid, p := range procs {
		add(pid, p[0], p[1])
	}
	// Entries that are not processes.
	if err := os.WriteFile(filepath.Join(root, "uptime"), []byte("1 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRunningFindsAProcessOnTheHost(t *testing.T) {
	root := fakeProc(t, "pid:[4026531836]", map[string][2]string{
		"1":   {"systemd", "pid:[4026531836]"},
		"812": {"postgres", "pid:[4026531836]"},
	})
	if !runningIn(root, []string{"postgres"}) {
		t.Fatal("a server on the host was not found")
	}
	if runningIn(root, []string{"mysqld", "mariadbd"}) {
		t.Fatal("found a server that is not running")
	}
	if !runningIn(root, []string{"mysqld", "postgres"}) {
		t.Fatal("any of the names should match")
	}
}

func TestRunningIgnoresAProcessInsideAContainer(t *testing.T) {
	root := fakeProc(t, "pid:[4026531836]", map[string][2]string{
		"1":     {"systemd", "pid:[4026531836]"},
		"40112": {"postgres", "pid:[4026532999]"},
		"40150": {"postgres", "pid:[4026532999]"},
	})
	if runningIn(root, []string{"postgres"}) {
		t.Fatal("a database inside a container was taken for one on the host")
	}
}

func TestRunningMatchesTheWholeNameOnly(t *testing.T) {
	root := fakeProc(t, "pid:[4026531836]", map[string][2]string{
		"7": {"postgres_exporter", "pid:[4026531836]"},
	})
	if runningIn(root, []string{"postgres"}) {
		t.Fatal("a longer name matched")
	}
}

// Without permission to read another process's namespace the answer has to
// be "local": the alternative is to stop monitoring a real server.
func TestRunningCountsAnUnreadableNamespaceAsLocal(t *testing.T) {
	root := fakeProc(t, "pid:[4026531836]", map[string][2]string{
		"812": {"mysqld", ""},
	})
	if !runningIn(root, []string{"mysqld"}) {
		t.Fatal("a process whose namespace cannot be read was ignored")
	}
}
