//go:build windows

package fim

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// stateDirSDDL is a protected DACL (no inheritance from ProgramData, whose
// default grants every user create rights) giving full control to SYSTEM and
// Administrators only, inherited by everything created inside.
const stateDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// manifestSDDL is the same protected DACL for the manifest file itself, so it
// is protected even in an operator-chosen directory with a looser ACL.
const manifestSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// checkTrust requires the manifest and its directory to be owned by SYSTEM,
// Administrators, or the account the agent runs as. Any other owner could
// have planted or rewritten the baseline.
func checkTrust(path string, _ *os.File) (bool, error) {
	self, err := currentUserSID()
	if err != nil {
		return false, fmt.Errorf("%w: %v", errManifestUntrusted, err)
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return false, fmt.Errorf("%w: reading owner of %s: %v", errManifestUntrusted, p, err)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil {
			return false, fmt.Errorf("%w: %s has no readable owner", errManifestUntrusted, p)
		}
		if !owner.IsWellKnown(windows.WinLocalSystemSid) &&
			!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) &&
			!owner.Equals(self) {
			return false, fmt.Errorf("%w: %s is owned by %s", errManifestUntrusted, p, owner.String())
		}
	}
	return false, nil
}

func currentUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid, nil
}

// ensureStateDir creates the manifest directory with stateDirSDDL. An
// existing directory is left as it is; checkTrust refuses it on load if it is
// owned by anyone else, and protectFile secures the manifest regardless.
func ensureStateDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(stateDirSDDL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return nil
}

// protectFile replaces the file's DACL with manifestSDDL.
func protectFile(path string) error {
	sd, err := windows.SecurityDescriptorFromString(manifestSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
