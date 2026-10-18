//go:build linux

package process

import "testing"

// An empty process_name is a substring of every command line and must not
// match anything.
func TestFindPID_EmptyNameMatchesNothing(t *testing.T) {
	if pid := findPID(""); pid != 0 {
		t.Errorf("findPID(\"\") = %d, want 0", pid)
	}
}
