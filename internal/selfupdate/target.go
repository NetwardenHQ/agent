package selfupdate

import (
	"fmt"
	"net/url"
	"runtime"
	"strings"
)

// Offer is what the server proposed in the /agent/data reply.
//
// It is a suggestion. Local configuration outranks every field, and it never
// carries which signing identity to trust.
type Offer struct {
	Version string
	URL     string
	SHA256  string
}

// Target is the resolved decision: exactly what to fetch, what it must hash
// to, and which version it must turn out to be.
type Target struct {
	Version string
	// Current is the version running now. The installer's own embedded
	// version must be newer than this, not just the offered string.
	Current string
	URL     string
	// SHA256 is empty when the server did not supply one. The signature check
	// still applies; the digest means a compromised download host alone cannot
	// serve different bytes.
	SHA256 string
}

// safeVersion allows only what a release can actually produce: digits, dots
// and a short alphanumeric suffix.
//
// The version arrives over the network and ends up inside a URL and a
// filename, so anything that could escape either (a slash, a dot segment,
// whitespace, a control character, a shell metacharacter) is refused.
func safeVersion(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	seenDigit := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			seenDigit = true
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '.' || c == '-' || c == '~':
		default:
			return false
		}
	}
	return seenDigit && !strings.Contains(v, "..")
}

// goosName / goarchName are the tokens used in published artifact filenames.
func goosName() string { return runtime.GOOS }

func goarchName() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("no installer published for %s", runtime.GOARCH)
	}
}

// expandTemplate fills {version}, {os} and {arch} in a locally configured
// download URL.
func expandTemplate(tmpl, version string) (string, error) {
	arch, err := goarchName()
	if err != nil {
		return "", err
	}
	r := strings.NewReplacer(
		"{version}", version,
		"{os}", goosName(),
		"{arch}", arch,
	)
	return r.Replace(tmpl), nil
}

// resolveTarget decides where the installer actually comes from.
//
// Precedence:
//
//  1. A locally configured URL template wins outright, so nothing the server
//     says can send an airgapped site, or one running its own build, to a
//     vendor host.
//  2. Otherwise the server's URL is used. It is configurable on the platform
//     side so a self-hosted install points at its own repository.
//
// Either way the URL must be absolute HTTPS, and the version must be a shape
// a release can actually produce. Plain HTTP is refused: the signature check
// would still catch tampering, but there is no reason to hand an on-path
// observer the inventory of which hosts are upgrading and when.
func resolveTarget(offer Offer, cfg Config) (Target, error) {
	if !safeVersion(offer.Version) {
		return Target{}, fmt.Errorf("refusing unsafe version string %q", offer.Version)
	}

	raw := offer.URL
	fromLocal := false
	if cfg.URLTemplate != "" {
		expanded, err := expandTemplate(cfg.URLTemplate, offer.Version)
		if err != nil {
			return Target{}, err
		}
		raw = expanded
		fromLocal = true
	}

	if raw == "" {
		return Target{}, fmt.Errorf("no download URL offered and none configured locally")
	}
	if err := validateDownloadURL(raw); err != nil {
		return Target{}, err
	}

	t := Target{Version: offer.Version, Current: cfg.CurrentVersion, URL: raw}
	// A locally configured mirror serves whatever the operator put there,
	// which will not match the vendor's published digest; the signature check
	// still applies.
	if !fromLocal {
		t.SHA256 = strings.ToLower(strings.TrimSpace(offer.SHA256))
		if t.SHA256 != "" && !isHex64(t.SHA256) {
			return Target{}, fmt.Errorf("offered sha256 is not a 64-character hex digest")
		}
	}
	return t, nil
}

func validateDownloadURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("download URL is not parseable: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("download URL must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("download URL has no host")
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
