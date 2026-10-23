//go:build windows

package security

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Whether the local audit policy records what the Security log reader looks
// for. A logon that Windows does not audit leaves no event, so without this
// an empty list would read as "nobody logged in". The agent never changes the
// policy; the host page says what to turn on.
//
// Subcategory GUIDs from Microsoft's advanced audit policy reference:
//
//	Logon                      {0CCE9215-69AE-11D9-BED3-505054503030}  4624, 4625
//	User Account Management    {0CCE9235-69AE-11D9-BED3-505054503030}  4720
//	Security Group Management  {0CCE9237-69AE-11D9-BED3-505054503030}  4732

var (
	modadvapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procAuditQuerySystemPolicy   = modadvapi32.NewProc("AuditQuerySystemPolicy")
	procAuditFree                = modadvapi32.NewProc("AuditFree")
	auditLogon                   = mustGUID("{0CCE9215-69AE-11D9-BED3-505054503030}")
	auditUserAccountManagement   = mustGUID("{0CCE9235-69AE-11D9-BED3-505054503030}")
	auditSecurityGroupManagement = mustGUID("{0CCE9237-69AE-11D9-BED3-505054503030}")
)

const (
	policyAuditEventSuccess = 0x1
	policyAuditEventFailure = 0x2
)

type auditPolicyInformation struct {
	AuditSubCategoryGUID windows.GUID
	AuditingInformation  uint32
	AuditCategoryGUID    windows.GUID
}

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}

// auditCoverage reports whether logon success and failure, and account and
// security-group changes, are audited. ok is false when the policy cannot be
// read (the query needs SeSecurityPrivilege); the caller then reports
// nothing rather than guessing.
func auditCoverage() (logon, accounts bool, ok bool) {
	if err := modadvapi32.Load(); err != nil {
		return false, false, false
	}
	guids := []windows.GUID{auditLogon, auditUserAccountManagement, auditSecurityGroupManagement}
	var info *auditPolicyInformation
	r, _, _ := procAuditQuerySystemPolicy.Call(uintptr(unsafe.Pointer(&guids[0])), uintptr(len(guids)),
		uintptr(unsafe.Pointer(&info)))
	if r == 0 || info == nil {
		return false, false, false
	}
	defer procAuditFree.Call(uintptr(unsafe.Pointer(info)))

	policies := unsafe.Slice(info, len(guids))
	both := uint32(policyAuditEventSuccess | policyAuditEventFailure)
	logon = policies[0].AuditingInformation&both == both
	accounts = policies[1].AuditingInformation&policyAuditEventSuccess != 0 &&
		policies[2].AuditingInformation&policyAuditEventSuccess != 0
	return logon, accounts, true
}
