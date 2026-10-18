package selfupdate

import (
	"runtime"
	"strings"
	"testing"
)

const goodSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestServerURLIsUsedWhenNothingConfiguredLocally(t *testing.T) {
	got, err := resolveTarget(
		Offer{Version: "3.0.1", URL: "https://selfhosted.example/agent.exe", SHA256: goodSHA},
		Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://selfhosted.example/agent.exe" {
		t.Fatalf("expected the server's URL, got %q", got.URL)
	}
	if got.SHA256 != goodSHA {
		t.Fatalf("expected the offered digest, got %q", got.SHA256)
	}
}

func TestLocalURLTemplateOverridesTheServer(t *testing.T) {
	if _, err := goarchName(); err != nil {
		t.Skipf("unsupported arch: %v", err)
	}
	got, err := resolveTarget(
		Offer{Version: "3.0.1", URL: "https://vendor.example/agent.exe", SHA256: goodSHA},
		Config{URLTemplate: "https://mirror.internal/nw-{version}-{os}-{arch}.exe"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.URL, "vendor.example") {
		t.Fatalf("local config must win, still got %q", got.URL)
	}
	if !strings.HasPrefix(got.URL, "https://mirror.internal/nw-3.0.1-") {
		t.Fatalf("template not expanded: %q", got.URL)
	}
	if !strings.Contains(got.URL, runtime.GOOS) {
		t.Fatalf("{os} not expanded: %q", got.URL)
	}
	// The vendor's digest cannot describe someone else's mirror.
	if got.SHA256 != "" {
		t.Fatalf("a locally mirrored download must not carry the vendor digest, got %q", got.SHA256)
	}
}

func TestRefusesNonHTTPS(t *testing.T) {
	for _, u := range []string{
		"http://vendor.example/agent.exe",
		"ftp://vendor.example/agent.exe",
		"file:///tmp/evil.exe",
		"\\\\smb\\share\\evil.exe",
	} {
		if _, err := resolveTarget(Offer{Version: "3.0.1", URL: u}, Config{}); err == nil {
			t.Errorf("URL %q should be refused", u)
		}
	}
}

func TestRefusesWhenNoURLAnywhere(t *testing.T) {
	if _, err := resolveTarget(Offer{Version: "3.0.1"}, Config{}); err == nil {
		t.Fatal("no URL offered and none configured should be an error")
	}
}

func TestRefusesUnsafeVersion(t *testing.T) {
	for _, v := range []string{"", "../evil", "3.0.0 x", "3.0.0;calc", "latest"} {
		_, err := resolveTarget(Offer{Version: v, URL: "https://ok.example/a.exe"}, Config{})
		if err == nil {
			t.Errorf("version %q should be refused", v)
		}
	}
}

func TestRefusesMalformedDigest(t *testing.T) {
	for _, h := range []string{"abc", "zz" + goodSHA[2:], goodSHA + "00"} {
		_, err := resolveTarget(
			Offer{Version: "3.0.1", URL: "https://ok.example/a.exe", SHA256: h}, Config{})
		if err == nil {
			t.Errorf("digest %q should be refused", h)
		}
	}
}

func TestAbsentDigestIsAllowed(t *testing.T) {
	// An older platform may not send one; the signature check still applies.
	got, err := resolveTarget(Offer{Version: "3.0.1", URL: "https://ok.example/a.exe"}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != "" {
		t.Fatalf("expected no digest, got %q", got.SHA256)
	}
}

func TestAcceptedSignersDefaultsAndOverride(t *testing.T) {
	if got := (Config{}).acceptedSigners(); len(got) == 0 {
		t.Fatal("there must always be a default signer list")
	}
	custom := Config{Signers: []string{"Acme Corp"}}.acceptedSigners()
	if len(custom) != 1 || custom[0] != "Acme Corp" {
		t.Fatalf("local signer override ignored: %v", custom)
	}
	// The override replaces the defaults rather than extending them, so trust
	// in the vendor certificate can be removed.
	if signerAccepted(identityOf(releaseSigner(t)), custom) {
		t.Fatal("overriding the signer list must drop the defaults")
	}
}
