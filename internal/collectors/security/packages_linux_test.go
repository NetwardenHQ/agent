//go:build linux

package security

import "testing"

// Real `dpkg-query -W -f=${Package}\t${Version}\t${Architecture}\n` output.
const dpkgOut = "openssl\t3.0.13-0ubuntu3.4\tamd64\n" +
	"libc6\t2.39-0ubuntu8.3\tamd64\n" +
	"python3-requests\t2.31.0+dfsg-1ubuntu1\tall\n" +
	"\t1.0\tamd64\n" + // no name -> dropped
	"malformed-line-without-tabs\n"

// Real `rpm -qa --queryformat %{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n` output.
const rpmOut = "openssl\t3.0.7-27.el9\tx86_64\n" +
	"glibc\t2.34-100.el9\tx86_64\n" +
	"kernel\t5.14.0-427.el9\tx86_64\n"

func TestParseDpkgOutput(t *testing.T) {
	pkgs := parseDpkgOutput(dpkgOut)

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages (nameless and malformed rows dropped), got %d: %+v", len(pkgs), pkgs)
	}

	openssl := pkgs[0]
	if openssl.Name != "openssl" || openssl.Version != "3.0.13-0ubuntu3.4" || openssl.Arch != "amd64" {
		t.Errorf("openssl mis-parsed: %+v", openssl)
	}

	// Ecosystem is what routes a package to the right vulnerability feed;
	// an unset value would send deb packages down the OSV path.
	for _, p := range pkgs {
		if p.Ecosystem != EcosystemDeb {
			t.Errorf("package %q has ecosystem %q, want %q", p.Name, p.Ecosystem, EcosystemDeb)
		}
		if p.Source != "dpkg" {
			t.Errorf("package %q has source %q, want dpkg", p.Name, p.Source)
		}
	}
}

func TestParseRPMOutput(t *testing.T) {
	pkgs := parseRPMOutput(rpmOut)

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "openssl" || pkgs[0].Version != "3.0.7-27.el9" || pkgs[0].Arch != "x86_64" {
		t.Errorf("openssl mis-parsed: %+v", pkgs[0])
	}
	for _, p := range pkgs {
		if p.Ecosystem != EcosystemRPM {
			t.Errorf("package %q has ecosystem %q, want %q", p.Name, p.Ecosystem, EcosystemRPM)
		}
		if p.Source != "rpm" {
			t.Errorf("package %q has source %q, want rpm", p.Name, p.Source)
		}
	}
}

// The OS ecosystems route to the distro advisory feeds; the language ones are
// reserved for host-installed language packages and must match the
// OsvEcosystem union on the platform side verbatim, or the module matcher
// silently finds no advisories for them.
func TestEcosystemIdentifiersMatchPlatformContract(t *testing.T) {
	osvEcosystems := map[string]bool{
		EcosystemNPM:      true,
		EcosystemPyPI:     true,
		EcosystemRubyGems: true,
		EcosystemGoMod:    true,
		EcosystemCargo:    true,
		EcosystemMaven:    true,
		EcosystemNuGet:    true,
		EcosystemComposer: true,
	}
	// Mirrors OsvEcosystem in platform/lib/security/cve-feeds/osv.ts.
	for _, want := range []string{
		"npm", "pypi", "rubygems", "gomod", "cargo", "maven", "nuget", "composer",
	} {
		if !osvEcosystems[want] {
			t.Errorf("platform declares OSV ecosystem %q with no matching agent constant", want)
		}
	}

	for _, os := range []string{EcosystemDeb, EcosystemRPM, EcosystemAPK} {
		if osvEcosystems[os] {
			t.Errorf("%q is an OS ecosystem and must not collide with an OSV one", os)
		}
	}
}
