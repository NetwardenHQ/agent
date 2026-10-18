package selfupdate

import "testing"

// platformURL and platformSHA have the shape of the hint the platform sends.
// The tests pin the contract between the platform and the agent's resolver.
const platformURL = "https://mirror.selfhosted.test/windows/netwarden-3.0.1-windows-amd64-installer.exe"
const platformSHA = "2222222222222222222222222222222222222222222222222222222222222222"

func TestAgentAcceptsTheHintThePlatformProduces(t *testing.T) {
	got, err := resolveTarget(
		Offer{Version: "3.0.1", URL: platformURL, SHA256: platformSHA},
		Config{}) // no local override: take the platform's word
	if err != nil {
		t.Fatalf("agent rejected a hint the platform produced: %v", err)
	}
	if got.URL != platformURL {
		t.Fatalf("URL mangled: %q", got.URL)
	}
	if got.SHA256 != platformSHA {
		t.Fatalf("digest mangled: %q", got.SHA256)
	}
	if got.Version != "3.0.1" {
		t.Fatalf("version mangled: %q", got.Version)
	}
}

func TestLocalOverrideBeatsThatSameHint(t *testing.T) {
	if _, err := goarchName(); err != nil {
		t.Skipf("unsupported arch: %v", err)
	}
	got, err := resolveTarget(
		Offer{Version: "3.0.1", URL: platformURL, SHA256: platformSHA},
		Config{URLTemplate: "https://airgap.internal/nw-{version}-{arch}.exe"})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL == platformURL {
		t.Fatal("local config must override the platform URL")
	}
	if got.SHA256 != "" {
		t.Fatal("a local mirror must not inherit the platform's digest")
	}
}
