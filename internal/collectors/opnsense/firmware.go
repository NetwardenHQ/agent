package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// firmwareStatus is /tmp/pkg_upgrade.json, written by OPNsense's own update
// check (scripts/firmware/check.sh, run by its "Firmware update check" cron).
type firmwareStatus struct {
	Connection         string            `json:"connection"`
	Repository         string            `json:"repository"`
	NeedsReboot        string            `json:"needs_reboot"`
	ProductID          string            `json:"product_id"`
	ProductVersion     string            `json:"product_version"`
	UpgradeMajorVer    string            `json:"upgrade_major_version"`
	UpgradeNeedsReboot string            `json:"upgrade_needs_reboot"`
	NewPackages        []json.RawMessage `json:"new_packages"`
	Reinstall          []json.RawMessage `json:"reinstall_packages"`
	Remove             []json.RawMessage `json:"remove_packages"`
	Downgrade          []json.RawMessage `json:"downgrade_packages"`
	Upgrade            []json.RawMessage `json:"upgrade_packages"`
	UpgradeSets        []json.RawMessage `json:"upgrade_sets"`
}

// maxFirmwareJSON bounds the status file; a full major upgrade lists a few
// hundred packages, well under this.
const maxFirmwareJSON = 4 << 20

func parseFirmware(data []byte) (firmwareStatus, error) {
	var f firmwareStatus
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("firmware status is not valid JSON: %w", err)
	}
	if f.Connection == "" || f.Repository == "" {
		return f, fmt.Errorf("firmware status lacks connection/repository fields")
	}
	return f, nil
}

// collectFirmware reports what OPNsense's last update check found. The check
// itself belongs to OPNsense (it is a cron job there); the agent only reads
// the result, so it never opens a connection to the firmware mirrors.
func (c *Collector) collectFirmware(_ context.Context, e *emitter) error {
	data, info, err := readTrustedFile(c.firmwareJSON, c.firmwareOwner, maxFirmwareJSON)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no firmware status file (has the OPNsense update check ever run?): %w", err)
	}
	if err != nil {
		return err
	}
	f, err := parseFirmware(data)
	if err != nil {
		return err
	}

	ok := f.Connection == "ok" && f.Repository == "ok"
	e.gauge("opnsense_firmware_check_ok", b2f(ok), map[string]string{
		"connection": f.Connection, "repository": f.Repository,
	})
	e.gauge("opnsense_firmware_check_age_seconds", e.ts.Sub(info.ModTime()).Seconds(), nil)
	e.gauge("opnsense_info", 1, map[string]string{
		"product_id": f.ProductID, "product_version": f.ProductVersion,
	})

	// Package counts are only meaningful when the check reached the mirrors.
	if ok {
		e.gauge("opnsense_firmware_upgrade_packages", float64(len(f.Upgrade)), nil)
		e.gauge("opnsense_firmware_new_packages", float64(len(f.NewPackages)), nil)
		e.gauge("opnsense_firmware_remove_packages", float64(len(f.Remove)), nil)
		e.gauge("opnsense_firmware_reinstall_packages", float64(len(f.Reinstall)), nil)
		e.gauge("opnsense_firmware_downgrade_packages", float64(len(f.Downgrade)), nil)
		// A major upgrade (e.g. 26.1 -> 26.7) arrives as upgrade_sets
		// (base/kernel) and a version string, not as package updates.
		e.gauge("opnsense_firmware_major_upgrade_available", b2f(strings.TrimSpace(f.UpgradeMajorVer) != "" || len(f.UpgradeSets) > 0),
			map[string]string{"version": strings.TrimSpace(f.UpgradeMajorVer)})
	}
	e.gauge("opnsense_reboot_required", b2f(f.NeedsReboot == "1" || f.UpgradeNeedsReboot == "1"), nil)
	return nil
}
