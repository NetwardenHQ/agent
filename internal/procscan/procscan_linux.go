//go:build linux

package procscan

import (
	"os"
	"path/filepath"
	"strings"
)

// Running reports whether a process named one of names (the kernel's short
// name, as `pgrep -x` matches it) runs in the agent's own PID namespace.
//
// A database inside a container is visible in the host's process table, but
// it is not a server the agent can reach on the host's sockets or loopback.
// Treating it as local would report a healthy containerized database as one
// the agent cannot connect to. Such a process lives in another PID namespace,
// which is how it is told apart. A process whose namespace cannot be read is
// counted as local.
func Running(names ...string) bool {
	return runningIn("/proc", names)
}

func runningIn(procRoot string, names []string) bool {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	own, ownErr := os.Readlink(filepath.Join(procRoot, "self", "ns", "pid"))
	for _, e := range entries {
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(procRoot, pid, "comm"))
		if err != nil || !want[strings.TrimSpace(string(comm))] {
			continue
		}
		ns, err := os.Readlink(filepath.Join(procRoot, pid, "ns", "pid"))
		if err != nil || ownErr != nil || ns == own {
			return true
		}
	}
	return false
}
