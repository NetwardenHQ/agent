//go:build windows

package security

import (
	"context"
	"strings"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"
)

// Enabled: on Windows the inventory is the OS build, the installed updates
// and the installed programs (windows_inventory.go).
func (c *PackagesCollector) Enabled() bool {
	return true
}

// Collect reports the Windows inventory every PackagesCollectionInterval, like
// the dpkg/rpm inventory on Linux, and re-emits the gauges between runs.
func (c *PackagesCollector) Collect(ctx context.Context) ([]metrics.Metric, error) {
	timestamp := time.Now()
	due, cached := c.shouldCollect(timestamp)
	if !due {
		refreshed := make([]metrics.Metric, 0, len(cached))
		for _, m := range cached {
			m.Timestamp = timestamp
			refreshed = append(refreshed, m)
		}
		return refreshed, nil
	}
	c.builder = c.builder.WithTimestamp(timestamp)

	osInfo, err := readWindowsOS()
	if err != nil {
		c.logger.Warn("could not read the Windows version from the registry", "error", err)
	}
	hotfixes, err := readWindowsHotfixes(ctx)
	if err != nil {
		c.logger.Warn("could not list installed Windows updates", "error", err)
	}
	programs := cleanWindowsPrograms(readWindowsPrograms())

	collected := make([]metrics.Metric, 0, 2)
	add := func(name string, value float64, labels map[string]string) {
		m, err := c.builder.GaugeWithLabels(name, value, labels)
		if err != nil {
			c.logger.Warn("failed to build metric", "name", name, "error", err)
			return
		}
		collected = append(collected, m)
	}
	add("security_packages_distro_id", 1.0, map[string]string{"distro_id": "windows", "distro_version_id": osInfo.fullBuild()})
	add("security_installed_package_count", float64(len(programs)), map[string]string{"source": "windows_program"})

	// Without a full build (10.0.<build>.<UBR>) the OS cannot be matched; an
	// inventory without it would read as a Windows host with nothing to fix,
	// or, with a guessed revision, as one missing every update.
	if osInfo.fullBuild() == "" {
		c.unsupportedOnce.Do(func() {
			c.logger.Info("windows inventory not sent: no Windows 10-based build with an update revision",
				"major", osInfo.MajorVersion, "build", osInfo.CurrentBuild, "has_ubr", osInfo.HasUBR)
		})
		c.store(collected, metrics.Snapshot{})
		c.clearPending()
		return collected, nil
	}
	c.store(collected, metrics.Snapshot{
		Type:    metrics.SnapshotInstalledPackages,
		Payload: windowsInventoryPayload(osInfo, hotfixes, programs),
	})
	c.logger.Debug("windows inventory collected", "build", osInfo.fullBuild(), "hotfixes", len(hotfixes), "programs", len(programs))
	return collected, nil
}

func readWindowsOS() (windowsOS, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return windowsOS{}, err
	}
	defer k.Close()
	str := func(name string) string {
		v, _, err := k.GetStringValue(name)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(v)
	}
	o := windowsOS{
		ProductName:      str("ProductName"),
		EditionID:        str("EditionID"),
		DisplayVersion:   str("DisplayVersion"),
		InstallationType: str("InstallationType"),
		CurrentBuild:     str("CurrentBuild"),
	}
	if ubr, _, err := k.GetIntegerValue("UBR"); err == nil {
		o.UBR = ubr
		o.HasUBR = true
	}
	if major, _, err := k.GetIntegerValue("CurrentMajorVersionNumber"); err == nil {
		o.MajorVersion = major
	}
	return o, nil
}

type win32QuickFixEngineering struct {
	HotFixID string
}

func readWindowsHotfixes(ctx context.Context) ([]string, error) {
	type result struct {
		rows []win32QuickFixEngineering
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var rows []win32QuickFixEngineering
		err := wmi.Query("SELECT HotFixID FROM Win32_QuickFixEngineering", &rows)
		ch <- result{rows, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		out := make([]string, 0, len(r.rows))
		for _, row := range r.rows {
			out = append(out, row.HotFixID)
		}
		return out, nil
	}
}

// readWindowsPrograms reads the Uninstall lists: both registry views of the
// machine-wide key (64-bit programs, and 32-bit ones under WOW6432Node), and
// the key in each signed-in user's hive under HKEY_USERS, where programs
// installed "just for me" are listed (Zoom installs that way by default, and
// Chrome, Git and VS Code can). Users not signed in have no hive loaded, so
// their per-user programs are not seen until they sign in.
func readWindowsPrograms() []windowsProgram {
	const uninstall = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	var out []windowsProgram
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		out = append(out, readUninstallKey(registry.LOCAL_MACHINE, uninstall, view)...)
	}
	users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		sids, err := users.ReadSubKeyNames(-1)
		users.Close()
		if err == nil {
			for _, sid := range sids {
				if isUserSID(sid) {
					out = append(out, readUninstallKey(registry.USERS, sid+`\`+uninstall, 0)...)
				}
			}
		}
	}
	return out
}

// readUninstallKey lists the programs under one Uninstall key.
func readUninstallKey(root registry.Key, path string, view uint32) []windowsProgram {
	parent, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|view)
	if err != nil {
		return nil
	}
	names, err := parent.ReadSubKeyNames(-1)
	parent.Close()
	if err != nil {
		return nil
	}
	var out []windowsProgram
	for _, name := range names {
		k, err := registry.OpenKey(root, path+`\`+name, registry.QUERY_VALUE|view)
		if err != nil {
			continue
		}
		p := windowsProgram{}
		p.Name, _, _ = k.GetStringValue("DisplayName")
		p.Version, _, _ = k.GetStringValue("DisplayVersion")
		p.Publisher, _, _ = k.GetStringValue("Publisher")
		if sc, _, err := k.GetIntegerValue("SystemComponent"); err == nil && sc == 1 {
			p.SystemComponent = true
		}
		k.Close()
		out = append(out, p)
	}
	return out
}
