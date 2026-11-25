package security

import (
	"fmt"
	"sort"
	"strings"
)

// EcosystemWindows tags programs from the Windows "installed programs" list
// (the registry Uninstall keys). The platform matches the OS itself by build
// against Microsoft's security updates, and programs by name and version.
const EcosystemWindows = "windows"

// windowsOS is what HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion says
// about the installed Windows. CurrentBuild plus UBR (update build revision)
// is what Microsoft's security update data lists as the build that fixes a
// CVE, so it is the match key.
type windowsOS struct {
	ProductName      string
	EditionID        string
	DisplayVersion   string
	InstallationType string // "Client" or "Server"
	CurrentBuild     string
	// MajorVersion is CurrentMajorVersionNumber: 10 on Windows 10, 11 and
	// Server 2016 onwards; absent (0) on Windows 8.1 / Server 2012 R2 and older.
	MajorVersion uint64
	UBR          uint64
	HasUBR       bool
}

// fullBuild is 10.0.<build>.<UBR>, the form Microsoft's update data uses, or
// "" when the host cannot be matched by it: not Windows 10-based (8.1 is 6.3,
// and its builds are not in that data), no build number, or no update
// revision. A missing UBR must not be reported as .0: that would read as a
// host that never installed an update, and flag every Windows CVE.
func (o windowsOS) fullBuild() string {
	if o.MajorVersion != 10 || o.CurrentBuild == "" || !o.HasUBR {
		return ""
	}
	return fmt.Sprintf("10.0.%s.%d", o.CurrentBuild, o.UBR)
}

// isUserSID says whether a key under HKEY_USERS is a signed-in person's own
// hive (S-1-5-21-…), not .DEFAULT, a service account (S-1-5-18/19/20) or a
// _Classes key. Programs installed "just for me" are listed there only.
func isUserSID(name string) bool {
	if !strings.HasPrefix(name, "S-1-5-21-") || strings.HasSuffix(name, "_Classes") {
		return false
	}
	for _, r := range name[len("S-1-5-21-"):] {
		if (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// windowsProgram is one entry of an Uninstall key.
type windowsProgram struct {
	Name            string
	Version         string
	Publisher       string
	SystemComponent bool // hidden from Apps & Features (SystemComponent=1)
}

// cleanWindowsPrograms keeps the programs a person would recognise: named,
// not system components, once each (the 32- and 64-bit registry views often
// list the same program), sorted by name.
func cleanWindowsPrograms(in []windowsProgram) []installedPackage {
	seen := map[string]bool{}
	out := []installedPackage{}
	for _, p := range in {
		name := strings.TrimSpace(p.Name)
		if name == "" || p.SystemComponent {
			continue
		}
		version := strings.TrimSpace(p.Version)
		key := strings.ToLower(name) + "\x00" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, installedPackage{Name: name, Version: version, Source: "windows_program", Ecosystem: EcosystemWindows})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// windowsInventoryPayload is the installed_packages snapshot for a Windows
// host: the OS build (distro_version_id, the CVE join key), the installed
// updates and the programs.
func windowsInventoryPayload(os windowsOS, hotfixes []string, programs []installedPackage) map[string]any {
	kb := map[string]bool{}
	for _, h := range hotfixes {
		h = strings.ToUpper(strings.TrimSpace(h))
		if h != "" {
			kb[h] = true
		}
	}
	list := make([]string, 0, len(kb))
	for h := range kb {
		list = append(list, h)
	}
	sort.Strings(list)
	if programs == nil {
		programs = []installedPackage{}
	}
	return map[string]any{
		"packages":          programs,
		"distro_id":         "windows",
		"distro_version_id": os.fullBuild(),
		"windows": map[string]any{
			"product_name":      os.ProductName,
			"edition_id":        os.EditionID,
			"display_version":   os.DisplayVersion,
			"installation_type": os.InstallationType,
			"build":             os.CurrentBuild,
			"ubr":               os.UBR,
			"hotfixes":          list,
		},
	}
}
