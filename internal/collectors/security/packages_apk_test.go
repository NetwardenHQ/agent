package security

import "testing"

func TestParseApkInstalled(t *testing.T) {
	db := "C:Q1abc=\nP:musl\nV:1.2.5-r0\nA:x86_64\n\nC:Q1def=\nP:busybox\nV:1.36.1-r29\nA:x86_64\n\nP:broken\n\n"
	got := parseApkInstalled(db)
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(got), got)
	}
	if got[0].Name != "musl" || got[0].Version != "1.2.5-r0" || got[0].Arch != "x86_64" || got[0].Ecosystem != EcosystemAPK || got[0].Source != "apk" {
		t.Errorf("first package = %+v", got[0])
	}
	if got[1].Name != "busybox" || got[1].Version != "1.36.1-r29" {
		t.Errorf("second package = %+v", got[1])
	}
}

func TestClassifyAlpine(t *testing.T) {
	if classifyDistro(distroInfo{ID: "alpine"}) != pkgFamilyAlpine {
		t.Error("alpine is not classified as the apk family")
	}
}

func TestClassifySuse(t *testing.T) {
	for _, d := range []distroInfo{{ID: "sles", IDLike: "suse"}, {ID: "opensuse-leap", IDLike: "suse opensuse"}} {
		if classifyDistro(d) != pkgFamilyRHEL {
			t.Errorf("%s is not read with rpm", d.ID)
		}
	}
}
