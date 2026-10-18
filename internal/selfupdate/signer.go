package selfupdate

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// Signer allowlist entries come in three forms:
//
//	spki-sha256:<64 hex>   SHA-256 of the signing certificate's
//	                       SubjectPublicKeyInfo. Survives a renewal that
//	                       keeps the same key.
//	sha256:<64 hex>        SHA-256 thumbprint of the signing certificate
//	                       itself (certutil -hashfile / the "Thumbprint" a
//	                       SHA-256 view shows). Changes on every renewal.
//	anything else          the certificate's Common Name, matched exactly.
//
// A name is the weakest form: a CA will issue a certificate with any CN to
// any organization that can prove that name, and names are not unique across
// jurisdictions. An allowlist should contain pins.
const (
	pinCertPrefix = "sha256:"
	pinSPKIPrefix = "spki-sha256:"
)

// defaultSigners are the code-signing identities trusted out of the box.
//
// A valid Authenticode signature is not sufficient: code-signing certificates
// can be bought, so "signed by somebody" would accept any signed malware. The
// signer must match one of these unless the operator overrides the list in
// netwarden.conf, as anyone running their own build does.
//
// The single entry pins the public key of the current release code-signing
// certificate (CN=Moriah LLC, issued 2026-05-30, expires 2027-05-28). There
// is deliberately no name entry next to it: an accept list is only as strong
// as its weakest entry, and a CN alone would let anyone who obtains a
// certificate called "Moriah LLC" sign an installer this agent runs.
//
// Renewal: the key lives on a hardware token, so a renewal that re-certifies
// the same key keeps this pin valid. A renewal with a new key (or a
// replacement token) does not: add the new key's pin here and ship that
// release before anything is signed with the new key, or agents on the old
// build will refuse the new installer. Hosts that miss that window need one
// manual install, or a local self_update_signers entry.
var defaultSigners = []string{
	pinSPKIPrefix + "4405584e442697d8370b6a0ea40afbb60a6c8885a46d3b7b6b5c89ec4a1b8873",
}

// signerIdentity is what an allowlist entry is compared against.
type signerIdentity struct {
	CommonName string
	CertSHA256 string // lowercase hex
	SPKISHA256 string // lowercase hex
}

// identityOf extracts the comparable identity from a signing certificate.
func identityOf(cert *x509.Certificate) signerIdentity {
	certSum := sha256.Sum256(cert.Raw)
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return signerIdentity{
		CommonName: cert.Subject.CommonName,
		CertSHA256: hex.EncodeToString(certSum[:]),
		SPKISHA256: hex.EncodeToString(spkiSum[:]),
	}
}

// signerAccepted matches a signer against the allowlist. Names compare
// against the Common Name only, and exactly: not the Organization, not a
// substring, not case-folded, so "Moriah LLC Impersonators" or O=Moriah LLC
// on someone else's CN cannot pass.
func signerAccepted(id signerIdentity, accepted []string) bool {
	for _, want := range accepted {
		want = strings.TrimSpace(want)
		switch {
		case want == "":
			continue
		case strings.HasPrefix(strings.ToLower(want), pinSPKIPrefix):
			if pin := strings.ToLower(want[len(pinSPKIPrefix):]); isHex64(pin) && pin == id.SPKISHA256 {
				return true
			}
		case strings.HasPrefix(strings.ToLower(want), pinCertPrefix):
			if pin := strings.ToLower(want[len(pinCertPrefix):]); isHex64(pin) && pin == id.CertSHA256 {
				return true
			}
		default:
			if id.CommonName != "" && want == id.CommonName {
				return true
			}
		}
	}
	return false
}
