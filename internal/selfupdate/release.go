package selfupdate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Release packages outside Windows (the macOS tarball, the FreeBSD package)
// carry no signature of their own. Instead the release manifest signs a short
// statement for each one, and the platform passes that signature and the
// signing certificate along with the update hint.
//
// The statement names the version, the artifact the agent expects for its
// own platform, and the SHA-256 of the file the agent downloaded. The agent
// builds it itself from those values, never from the hint, so a signature
// for one platform, version or file cannot be presented for another.
const releaseStatementPrefix = "netwarden-agent-release-v1\n"

func releaseStatement(version, platform, format, arch, sha256Hex string) []byte {
	return []byte(releaseStatementPrefix +
		version + "\n" + platform + "\n" + format + "\n" + arch + "\n" +
		strings.ToLower(sha256Hex) + "\n")
}

// verifyReleaseSignature checks a statement's signature against the
// certificate that came with the hint, and the certificate against the
// accepted signers.
//
// Only pins accept a release signature. Nothing here validates a certificate
// chain, so a certificate's name proves nothing: anyone can issue themselves
// one with the publisher's name. The key itself must be pinned, by its SPKI
// hash or by the certificate's own hash.
func verifyReleaseSignature(statement []byte, signatureB64, certificateB64 string, signers []string) error {
	if signatureB64 == "" {
		return errors.New("the release carries no signature")
	}
	if certificateB64 == "" {
		return errors.New("the release carries no signing certificate")
	}
	der, err := base64.StdEncoding.DecodeString(certificateB64)
	if err != nil {
		return fmt.Errorf("signing certificate is not base64: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("signing certificate does not parse: %w", err)
	}
	if !keyPinned(identityOf(cert), signers) {
		return fmt.Errorf("release signed by a key that is not pinned (spki-sha256:%s)", identityOf(cert).SPKISHA256)
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("signature is not base64: %w", err)
	}

	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		var digest []byte
		switch pub.Curve {
		case elliptic.P256():
			d := sha256.Sum256(statement)
			digest = d[:]
		case elliptic.P384():
			d := sha512.Sum384(statement)
			digest = d[:]
		default:
			return fmt.Errorf("unsupported signing curve %s", pub.Curve.Params().Name)
		}
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return errors.New("signature does not match the release")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, statement, sig) {
			return errors.New("signature does not match the release")
		}
	default:
		return fmt.Errorf("unsupported signing key type %T", cert.PublicKey)
	}
	return nil
}

// keyPinned accepts the pin forms of the signer allowlist and ignores names.
func keyPinned(id signerIdentity, accepted []string) bool {
	pins := make([]string, 0, len(accepted))
	for _, want := range accepted {
		w := strings.ToLower(strings.TrimSpace(want))
		if strings.HasPrefix(w, pinSPKIPrefix) || strings.HasPrefix(w, pinCertPrefix) {
			pins = append(pins, w)
		}
	}
	return signerAccepted(id, pins)
}
