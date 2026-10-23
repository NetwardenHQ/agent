package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultSpoolDir(t *testing.T) {
	cases := []struct{ goos, programData, want string }{
		{"freebsd", "", "/var/db/netwarden/spool"},
		{"linux", "", "/var/lib/netwarden/spool"},
		{"windows", `D:\PD`, filepath.Join(`D:\PD`, "Netwarden", "spool")},
		{"windows", "", filepath.Join(`C:\ProgramData`, "Netwarden", "spool")},
		{"darwin", "", ""},
	}
	for _, c := range cases {
		if got := defaultSpoolDir(c.goos, c.programData); got != c.want {
			t.Errorf("defaultSpoolDir(%q, %q) = %q, want %q", c.goos, c.programData, got, c.want)
		}
	}
}
