package selfupdate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// releaseVector is a statement signed by the release key on its hardware
// token, through the same signing step the release script runs.
type releaseVector struct {
	Version     string `json:"version"`
	Platform    string `json:"platform"`
	Format      string `json:"format"`
	Arch        string `json:"arch"`
	SHA256      string `json:"sha256"`
	Signature   string `json:"signature"`
	Certificate string `json:"certificate"`
}

func loadVector(t *testing.T) releaseVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/release-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	var v releaseVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReleaseSignedByTheReleaseKeyIsAcceptedByDefault(t *testing.T) {
	v := loadVector(t)
	stmt := releaseStatement(v.Version, v.Platform, v.Format, v.Arch, v.SHA256)
	if err := verifyReleaseSignature(stmt, v.Signature, v.Certificate, defaultSigners); err != nil {
		t.Fatalf("the release key's signature was rejected with the built-in pins: %v", err)
	}
}

func TestReleaseSignatureCoversEveryField(t *testing.T) {
	v := loadVector(t)
	tampered := map[string][]byte{
		"version":  releaseStatement("9.9.9", v.Platform, v.Format, v.Arch, v.SHA256),
		"platform": releaseStatement(v.Version, "freebsd15", v.Format, v.Arch, v.SHA256),
		"format":   releaseStatement(v.Version, v.Platform, "pkg", v.Arch, v.SHA256),
		"arch":     releaseStatement(v.Version, v.Platform, v.Format, "intel", v.SHA256),
		"digest":   releaseStatement(v.Version, v.Platform, v.Format, v.Arch, strings.Repeat("a", 64)),
	}
	for field, stmt := range tampered {
		if err := verifyReleaseSignature(stmt, v.Signature, v.Certificate, defaultSigners); err == nil {
			t.Errorf("a statement with a different %s was accepted", field)
		}
	}
}

// selfSigned returns a certificate for key, as the hint would carry it.
func selfSigned(t *testing.T, key crypto.Signer, cn string) (*x509.Certificate, string) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, base64.StdEncoding.EncodeToString(der)
}

func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return pinSPKIPrefix + hex.EncodeToString(sum[:])
}

func certPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return pinCertPrefix + hex.EncodeToString(sum[:])
}

func signP256(t *testing.T, key *ecdsa.PrivateKey, stmt []byte) string {
	t.Helper()
	digest := sha256.Sum256(stmt)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestReleaseAcceptsPinnedKeysOnly(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, certB64 := selfSigned(t, key, "Moriah LLC")
	stmt := releaseStatement("3.3.0", "freebsd15", "pkg", "amd64", strings.Repeat("b", 64))
	sig := signP256(t, key, stmt)

	if err := verifyReleaseSignature(stmt, sig, certB64, []string{spkiPin(cert)}); err != nil {
		t.Errorf("SPKI pin: %v", err)
	}
	if err := verifyReleaseSignature(stmt, sig, certB64, []string{certPin(cert)}); err != nil {
		t.Errorf("certificate pin: %v", err)
	}
	// Anyone can issue themselves a certificate with this name; nothing here
	// checks a chain, so a name must never be enough.
	if err := verifyReleaseSignature(stmt, sig, certB64, []string{"Moriah LLC"}); err == nil {
		t.Error("a name-only signer list accepted a release signature")
	}
	if err := verifyReleaseSignature(stmt, sig, certB64, defaultSigners); err == nil {
		t.Error("a key nobody pinned was accepted by the built-in signers")
	}
}

func TestReleaseAcceptsEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, certB64 := selfSigned(t, priv, "release")
	stmt := releaseStatement("3.3.0", "macos", "tarball", "intel", strings.Repeat("c", 64))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, stmt))
	if err := verifyReleaseSignature(stmt, sig, certB64, []string{spkiPin(cert)}); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseRefusesMissingOrMalformedInput(t *testing.T) {
	v := loadVector(t)
	stmt := releaseStatement(v.Version, v.Platform, v.Format, v.Arch, v.SHA256)
	cases := map[string][2]string{
		"no signature":         {"", v.Certificate},
		"no certificate":       {v.Signature, ""},
		"signature not base64": {"%%%", v.Certificate},
		"certificate not DER":  {v.Signature, base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
		"signature not ASN.1":  {base64.StdEncoding.EncodeToString([]byte("short")), v.Certificate},
	}
	for name, c := range cases {
		if err := verifyReleaseSignature(stmt, c[0], c[1], defaultSigners); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
