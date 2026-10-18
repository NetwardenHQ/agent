//go:build windows

package selfupdate

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Authenticode verification answers two independent questions, and both must
// pass before a downloaded binary is executed:
//
//  1. Is the file signed, with an intact signature chaining to a trusted
//     root? WinVerifyTrust answers this, the same call Windows itself makes,
//     rather than a Go reimplementation of PKCS#7, the PE hash and chain
//     validation.
//  2. Is the signer an accepted one? The signing certificate is matched
//     against the local allowlist (key pin, certificate pin, or exact CN). A
//     valid signature only proves that someone signed the file, and
//     code-signing certificates can be bought.

var (
	modwintrust             = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust      = modwintrust.NewProc("WinVerifyTrust")
	wintrustActionGenericV2 = windows.GUID{
		Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
		Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
	}
)

const (
	wtdUINone            = 2
	wtdRevokeWholeChain  = 1
	wtdChoiceFile        = 1
	wtdStateActionVerify = 1
	wtdStateActionClose  = 2
	wtdSaferFlag         = 0x100
	// Revocation is consulted from the local URL cache only: no CRL or OCSP
	// request is made, so an agent on a restricted network can still update.
	// A revocation this host has not cached is not seen, so a revoked
	// certificate can pass here. Revocation is therefore not part of the
	// guarantee; the signer pin limits which certificate can be used at all.
	wtdCacheOnlyURLRetrieval = 0x1000
)

type winTrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type winTrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	fileInfo            uintptr
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// verifyAuthenticode fails unless the file carries a trusted Authenticode
// signature and the signing certificate is one the local allowlist accepts.
// h is the caller's pinned handle on the same file.
func verifyAuthenticode(h windows.Handle, path string, accepted []string) error {
	if err := winVerifyTrust(h, path); err != nil {
		return err
	}
	cert, err := signerCertificate(path)
	if err != nil {
		return fmt.Errorf("could not read signer certificate: %w", err)
	}
	id := identityOf(cert)
	if !signerAccepted(id, accepted) {
		return fmt.Errorf("signed by %q (spki-sha256:%s), which is not an accepted signer",
			id.CommonName, id.SPKISHA256)
	}
	return nil
}

// winVerifyTrust answers question 1: intact signature, trusted chain. It
// verifies through the handle, so the file checked is the file pinned.
func winVerifyTrust(h windows.Handle, path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	fi := winTrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(winTrustFileInfo{})),
		pcwszFilePath: p,
		hFile:         h,
	}
	data := winTrustData{
		cbStruct:            uint32(unsafe.Sizeof(winTrustData{})),
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeWholeChain,
		dwUnionChoice:       wtdChoiceFile,
		fileInfo:            uintptr(unsafe.Pointer(&fi)),
		dwStateAction:       wtdStateActionVerify,
		dwProvFlags:         wtdSaferFlag | wtdCacheOnlyURLRetrieval,
	}

	rc, _, _ := procWinVerifyTrust.Call(
		0, // no parent window; UI is suppressed anyway
		uintptr(unsafe.Pointer(&wintrustActionGenericV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	// Always close the state handle, whatever the verdict.
	data.dwStateAction = wtdStateActionClose
	_, _, _ = procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&wintrustActionGenericV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	if rc != 0 {
		return fmt.Errorf("WinVerifyTrust rejected the file (0x%x)", uint32(rc))
	}
	return nil
}

// signerCertificate answers question 2: who signed it.
//
// Shelling out to PowerShell rather than walking the certificate with
// CryptQueryObject keeps a large amount of fiddly CGO-free syscall code out
// of the agent. It runs only after WinVerifyTrust has accepted the file,
// while the caller still holds it pinned, and its output (the DER
// certificate, base64) is parsed and compared, never executed. PowerShell is
// started by absolute path so nothing on PATH can stand in for it.
func signerCertificate(path string) (*x509.Certificate, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-Command",
		"$c = (Get-AuthenticodeSignature -LiteralPath $env:NW_UPDATE_PATH).SignerCertificate; "+
			"if ($c) { [Convert]::ToBase64String($c.RawData) }")
	cmd.Env = append(cmd.Environ(), "NW_UPDATE_PATH="+path)

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	b64 := strings.TrimSpace(string(out))
	if b64 == "" {
		return nil, fmt.Errorf("no signer certificate on %s", path)
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("signer certificate is not base64: %w", err)
	}
	return x509.ParseCertificate(der)
}
