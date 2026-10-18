//go:build windows

package winsec

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProtectedSDDL is the security descriptor for directories only SYSTEM and
// Administrators may touch: full control for both, inherited by everything
// created inside, and P(rotected) so nothing is inherited from the parent
// (ProgramData, for example, lets every user create files in its subfolders).
const ProtectedSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// writeRights is every right that lets the holder change the object, its
// contents, or who may: data, append (for a directory, "add file" and "add
// subdirectory"), attributes, deletion of the object or its children, and the
// DACL or owner itself.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

const fileDeleteChild = 0x40

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

const secInfo = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION

// CheckHandle verifies an open file or directory.
func CheckHandle(h windows.Handle) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, secInfo)
	if err != nil {
		return fmt.Errorf("read security descriptor: %w", err)
	}
	return check(sd)
}

// CheckPath verifies a path. Prefer CheckHandle on an object already open, so
// the object checked is the object used.
func CheckPath(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, secInfo)
	if err != nil {
		return fmt.Errorf("read security descriptor: %w", err)
	}
	return check(sd)
}

func check(sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("cannot determine owner")
	}
	if !privileged(owner) {
		return fmt.Errorf("owned by %s, want SYSTEM or Administrators", owner.String())
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("NULL DACL grants everyone full control")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d: %w", i, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // applies to children only; they are checked themselves
		}
		if denyType(ace.Header.AceType) {
			continue
		}
		if ace.Mask&writeRights == 0 {
			continue
		}
		// Any other allow type that grants write is refused: the SID sits at
		// this offset only in the basic ACE, and an object or callback ACE
		// would be misread.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("DACL has an allow entry of type %d granting write", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if privileged(sid) || sid.IsWellKnown(windows.WinCreatorOwnerSid) {
			// CREATOR OWNER is a placeholder for the owner, already checked.
			continue
		}
		return fmt.Errorf("DACL grants write access to %s", sid.String())
	}
	return nil
}

func denyType(t uint8) bool {
	switch t {
	case windows.ACCESS_DENIED_ACE_TYPE,
		0x6, // ACCESS_DENIED_OBJECT_ACE_TYPE
		0xa, // ACCESS_DENIED_CALLBACK_ACE_TYPE
		0xc: // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
		return true
	}
	return false
}

func privileged(sid *windows.SID) bool {
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	if ti, err := windows.StringToSid(trustedInstallerSID); err == nil && sid.Equals(ti) {
		return true
	}
	return false
}

// MkdirProtected creates dir with ProtectedSDDL. If dir already exists it is
// left alone and must pass CheckPath: someone may have pre-created it, and
// re-applying a DACL to a directory an attacker owns would not undo what
// they already put inside.
func MkdirProtected(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(ProtectedSDDL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	err = windows.CreateDirectory(p, sa)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		fi, lerr := os.Lstat(dir)
		if lerr != nil {
			return lerr
		}
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s exists and is not a plain directory", dir)
		}
		if cerr := CheckPath(dir); cerr != nil {
			return fmt.Errorf("%s exists but is not protected: %w", dir, cerr)
		}
		return nil
	}
	return err
}
