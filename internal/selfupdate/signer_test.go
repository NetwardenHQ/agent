package selfupdate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// releaseSigner is the public leaf certificate releases are signed with.
func releaseSigner(t *testing.T) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile("testdata/release-signer.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block in testdata/release-signer.pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// lookalike is a certificate anyone could obtain: same names, different key.
func lookalike(t *testing.T, cn, org string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestDefaultSignersAcceptTheReleaseCertificate(t *testing.T) {
	if !signerAccepted(identityOf(releaseSigner(t)), defaultSigners) {
		t.Fatal("the release signing certificate must pass the default allowlist")
	}
}

func TestDefaultSignersRejectACertificateThatOnlySharesTheName(t *testing.T) {
	fake := lookalike(t, "Moriah LLC", "Moriah LLC")
	if signerAccepted(identityOf(fake), defaultSigners) {
		t.Fatal("a certificate that only carries the release signer's name must be refused")
	}
}

func TestPinsAndNames(t *testing.T) {
	real := identityOf(releaseSigner(t))
	other := identityOf(lookalike(t, "Somebody Else", "Moriah LLC"))

	cases := []struct {
		name     string
		accepted []string
		id       signerIdentity
		want     bool
	}{
		{"cert thumbprint", []string{"sha256:" + real.CertSHA256}, real, true},
		{"thumbprint is case-insensitive", []string{"SHA256:" + upper(real.CertSHA256)}, real, true},
		{"spki pin", []string{"spki-sha256:" + real.SPKISHA256}, real, true},
		{"spki pin is not a thumbprint", []string{"sha256:" + real.SPKISHA256}, real, false},
		{"malformed pin never matches", []string{"sha256:abc"}, signerIdentity{CertSHA256: "abc"}, false},
		{"exact CN", []string{"Moriah LLC"}, real, true},
		{"organization is not the CN", []string{"Moriah LLC"}, other, false},
		{"CN is not case-folded", []string{"moriah llc"}, real, false},
		{"CN is not a substring", []string{"Moriah"}, real, false},
		{"longer CN", []string{"Moriah LLC"}, signerIdentity{CommonName: "Moriah LLC Impersonators"}, false},
		{"empty CN never matches", []string{""}, signerIdentity{}, false},
		{"empty allowlist", nil, real, false},
	}
	for _, c := range cases {
		if got := signerAccepted(c.id, c.accepted); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
