package security

import (
	"reflect"
	"testing"
)

func TestWindowsFullBuild(t *testing.T) {
	os := windowsOS{MajorVersion: 10, CurrentBuild: "22631", UBR: 4602, HasUBR: true}
	if got := os.fullBuild(); got != "10.0.22631.4602" {
		t.Fatalf("fullBuild = %q", got)
	}
	// A revision of 0 is real (a fresh install) when the registry says so.
	if got := (windowsOS{MajorVersion: 10, CurrentBuild: "26100", HasUBR: true}).fullBuild(); got != "10.0.26100.0" {
		t.Fatalf("fullBuild with UBR 0 = %q", got)
	}
	for name, o := range map[string]windowsOS{
		"no build":           {MajorVersion: 10, UBR: 4602, HasUBR: true},
		"no UBR in registry": {MajorVersion: 10, CurrentBuild: "22631"},
		// Windows 8.1 / Server 2012 R2: no CurrentMajorVersionNumber, build 9600.
		"not Windows 10-based": {CurrentBuild: "9600", UBR: 21620, HasUBR: true},
	} {
		if got := o.fullBuild(); got != "" {
			t.Fatalf("%s: fullBuild = %q, want empty", name, got)
		}
	}
}

func TestIsUserSID(t *testing.T) {
	for sid, want := range map[string]bool{
		"S-1-5-21-3623811015-3361044348-30300820-1013":         true,
		"S-1-5-21-3623811015-3361044348-30300820-1013_Classes": false,
		"S-1-5-18": false, // LocalSystem
		"S-1-5-19": false,
		".DEFAULT": false,
		"":         false,
	} {
		if got := isUserSID(sid); got != want {
			t.Fatalf("isUserSID(%q) = %v, want %v", sid, got, want)
		}
	}
}

func TestWindowsProgramsCleaned(t *testing.T) {
	in := []windowsProgram{
		{Name: "7-Zip 24.08 (x64)", Version: "24.08", Publisher: "Igor Pavlov"},
		{Name: "7-Zip 24.08 (x64)", Version: "24.08", Publisher: "Igor Pavlov"}, // 32- and 64-bit views
		{Name: "  ", Version: "1.0"}, // no name
		{Name: "Update for Windows (KB5034441)", Version: "", SystemComponent: true},
		{Name: "Mozilla Firefox (x64 en-US)", Version: "133.0", Publisher: "Mozilla"},
	}
	got := cleanWindowsPrograms(in)
	want := []installedPackage{
		{Name: "7-Zip 24.08 (x64)", Version: "24.08", Source: "windows_program", Ecosystem: EcosystemWindows},
		{Name: "Mozilla Firefox (x64 en-US)", Version: "133.0", Source: "windows_program", Ecosystem: EcosystemWindows},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestWindowsInventoryPayload(t *testing.T) {
	os := windowsOS{ProductName: "Windows 11 Pro", EditionID: "Professional", DisplayVersion: "23H2", InstallationType: "Client", MajorVersion: 10, CurrentBuild: "22631", UBR: 4602, HasUBR: true}
	p := windowsInventoryPayload(os, []string{"KB5048685", "KB5048685", "kb5047621"}, nil)
	if p["distro_id"] != "windows" || p["distro_version_id"] != "10.0.22631.4602" {
		t.Fatalf("distro fields = %v / %v", p["distro_id"], p["distro_version_id"])
	}
	w := p["windows"].(map[string]any)
	if w["build"] != "22631" || w["ubr"] != uint64(4602) || w["installation_type"] != "Client" {
		t.Fatalf("windows = %+v", w)
	}
	if !reflect.DeepEqual(w["hotfixes"], []string{"KB5047621", "KB5048685"}) {
		t.Fatalf("hotfixes = %v", w["hotfixes"])
	}
}
