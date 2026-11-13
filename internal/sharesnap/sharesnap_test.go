package sharesnap

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseName(t *testing.T) {
	for name, want := range map[string]time.Time{
		"GMT-06-2026.11.13-10.15.01":    time.Date(2026, 11, 13, 16, 15, 1, 0, time.UTC),
		"GMT+00-2026.01.02-03.04.05":    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"GMT+05-30-2026.01.02-03.04.05": time.Date(2026, 1, 1, 21, 34, 5, 0, time.UTC),
	} {
		got, ok := ParseName(name)
		if !ok || !got.Equal(want) {
			t.Errorf("%s: got %v %v, want %v", name, got, ok, want)
		}
	}
	for _, bad := range []string{"desktop.ini", "@data.meta", "GMT-06-2026.13.40-99.00.00", ""} {
		if _, ok := ParseName(bad); ok {
			t.Errorf("%q parsed as a snapshot", bad)
		}
	}
}

func TestListAndLocate(t *testing.T) {
	root := t.TempDir()
	vol := filepath.Join(root, "volume1")
	for _, d := range []string{
		"@sharesnap/homes/GMT-06-2026.11.13-09.00.01",
		"@sharesnap/homes/GMT-06-2026.11.13-10.00.01",
		"@sharesnap/homes/GMT-06-2026.11.13-08.00.01",
		"@sharesnap/data/GMT-06-2026.11.13-02.00.00",
	} {
		if err := os.MkdirAll(filepath.Join(vol, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(vol, "@sharesnap/homes/desktop.ini"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	shares, err := Shares(root + "/volume*")
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 2 || shares[0].Name != "data" || shares[1].Name != "homes" {
		t.Fatalf("shares = %+v", shares)
	}
	homes := shares[1]
	if len(homes.Snapshots) != 3 || homes.Snapshots[0].Name != "GMT-06-2026.11.13-10.00.01" {
		t.Fatalf("snapshots newest first = %+v", homes.Snapshots)
	}
	if got := homes.Interval(); got != time.Hour {
		t.Errorf("interval = %v", got)
	}

	file := filepath.Join(vol, "homes", "alice", "Documents", "Passwords.xls")
	share, rel, ok := Locate(file, root+"/volume*")
	if !ok || share.Name != "homes" || rel != filepath.Join("alice", "Documents", "Passwords.xls") {
		t.Fatalf("Locate = %+v %q %v", share, rel, ok)
	}
	if _, _, ok := Locate(filepath.Join(root, "elsewhere", "x"), root+"/volume*"); ok {
		t.Errorf("a path outside any share was located")
	}
}
