package synology

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NetwardenHQ/agent/internal/sharesnap"
)

// ---------------------------------------------------------------------------
// Drives: DSM's per-drive files, /run/synostorage/disks/<dev>/
// ---------------------------------------------------------------------------

// diskChecks are DSM's per-drive verdicts; each reads "normal" when fine and
// "not_support" when the drive cannot be judged on it.
var diskChecks = []string{"unc_status", "timeout_status", "reset_fail_status", "seq_status"}

// readField returns a drive file's first line, trimmed; "" when absent.
func readField(dir, name string) string {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line)
}

func readInt(dir, name string) (int, bool) {
	n, err := strconv.Atoi(readField(dir, name))
	return n, err == nil
}

func (c *Collector) collectDisks(e *emitter) error {
	entries, err := os.ReadDir(c.disksDir)
	if err != nil {
		return err
	}
	var names []string
	for _, ent := range entries {
		if ent.IsDir() {
			names = append(names, ent.Name())
		}
	}
	if len(names) == 0 {
		return errors.New("DSM lists no drives")
	}
	sort.Strings(names)

	unhealthy := 0
	maxTemp, minLife := -1, -1
	for _, dev := range names {
		dir := filepath.Join(c.disksDir, dev)
		// DSM numbers drives by bay ("Drive 2"); the device name is
		// sataN, which does not always match.
		name := dev
		if id, ok := readInt(dir, "id"); ok && id > 0 {
			name = fmt.Sprintf("Drive %d", id)
		}

		var problems []string
		smart := readField(dir, "smart")
		if smart != "" && smart != "normal" && smart != "not_support" {
			problems = append(problems, "smart "+smart)
		}
		for _, check := range diskChecks {
			if v := readField(dir, check); v != "" && v != "normal" && v != "not_support" {
				problems = append(problems, check+" "+v)
			}
		}
		for _, flag := range []string{"remain_life_danger", "below_remain_life_thr", "ssd_bad_block_over_thr"} {
			if readField(dir, flag) == "1" {
				problems = append(problems, flag)
			}
		}
		if readField(dir, "read_only") == "1" {
			problems = append(problems, "read_only")
		}
		badSectors, haveBad := readInt(dir, "bad_sec_ct")
		if haveBad && badSectors > 0 {
			problems = append(problems, "bad sectors")
		}

		healthy := len(problems) == 0
		if !healthy {
			unhealthy++
		}
		status := "normal"
		if !healthy {
			status = strings.Join(withoutSmart(problems), ", ")
		}
		e.gauge("synology_disk_healthy", b2f(healthy), map[string]string{
			"disk": name, "id": dev, "model": readField(dir, "model"), "type": readField(dir, "type"),
			"smart": smart, "status": status,
		})
		if haveBad && badSectors >= 0 {
			e.gauge("synology_disk_bad_sectors", float64(badSectors), map[string]string{"disk": name, "id": dev})
		}
		if t, ok := readInt(dir, "temperature"); ok && t > 0 {
			e.gauge("synology_disk_temperature_celsius", float64(t), map[string]string{"disk": name, "id": dev})
			if t > maxTemp {
				maxTemp = t
			}
		}
		if life, ok := readInt(dir, "remain_life"); ok && life >= 0 {
			e.gauge("synology_disk_remaining_life_percent", float64(life), map[string]string{"disk": name, "id": dev})
			if minLife < 0 || life < minLife {
				minLife = life
			}
		}
	}
	e.gauge("synology_disks_unhealthy", float64(unhealthy), nil)
	if maxTemp >= 0 {
		e.gauge("synology_disk_max_temperature_celsius", float64(maxTemp), nil)
	}
	if minLife >= 0 {
		e.gauge("synology_disk_min_remaining_life_percent", float64(minLife), nil)
	}
	return nil
}

// withoutSmart drops the SMART entry, which has its own label.
func withoutSmart(problems []string) []string {
	out := problems[:0:0]
	for _, p := range problems {
		if !strings.HasPrefix(p, "smart ") {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"smart"}
	}
	return out
}

// ---------------------------------------------------------------------------
// Volumes: /proc/mounts. DSM remounts a damaged btrfs or ext4 volume
// read-only, so a /volumeN mounted ro is a volume in trouble.
// ---------------------------------------------------------------------------

func (c *Collector) collectVolumes(e *emitter) error {
	data, err := os.ReadFile(c.mounts)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	bad := 0
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasPrefix(f[1], "/volume") || strings.Contains(f[1][len("/volume"):], "/") || seen[f[1]] {
			continue
		}
		seen[f[1]] = true
		readOnly := false
		for _, opt := range strings.Split(f[3], ",") {
			if opt == "ro" {
				readOnly = true
			}
		}
		status := "normal"
		if readOnly {
			status = "read-only"
			bad++
		}
		e.gauge("synology_volume_healthy", b2f(!readOnly), map[string]string{"volume": f[1], "status": status})
	}
	e.gauge("synology_volumes_unhealthy", float64(bad), nil)
	return nil
}

// ---------------------------------------------------------------------------
// The unit's temperature: the CPU package sensor (coretemp).
// ---------------------------------------------------------------------------

func (c *Collector) collectTemperature(e *emitter) error {
	dirs, err := os.ReadDir(c.hwmonDir)
	if err != nil {
		return err
	}
	hottest := -1
	for _, d := range dirs {
		dir := filepath.Join(c.hwmonDir, d.Name())
		if readField(dir, "name") != "coretemp" {
			continue
		}
		inputs, _ := filepath.Glob(filepath.Join(dir, "temp*_input"))
		for _, in := range inputs {
			if milli, ok := readInt(filepath.Dir(in), filepath.Base(in)); ok && milli/1000 > hottest {
				hottest = milli / 1000
			}
		}
	}
	if hottest < 0 {
		return errors.New("no coretemp sensor")
	}
	e.gauge("synology_system_temperature_celsius", float64(hottest), nil)
	return nil
}

// ---------------------------------------------------------------------------
// UPS: DSM's UPS service (NUT upsd) on localhost, which answers any local
// user. Nothing listening means no UPS is set up, which is not a failure.
// ---------------------------------------------------------------------------

const upsTimeout = 3 * time.Second

func (c *Collector) collectUPS(e *emitter) error {
	conn, err := net.DialTimeout("tcp", c.upsAddr, upsTimeout)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil
		}
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(upsTimeout))
	r := bufio.NewReader(conn)

	ask := func(cmd string) ([]string, error) {
		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			return nil, err
		}
		var lines []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return nil, err
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "ERR "):
				return nil, fmt.Errorf("upsd: %s", strings.TrimPrefix(line, "ERR "))
			case strings.HasPrefix(line, "BEGIN "):
			case strings.HasPrefix(line, "END "):
				return lines, nil
			default:
				lines = append(lines, line)
			}
		}
	}

	upsList, err := ask("LIST UPS")
	if err != nil {
		return err
	}
	if len(upsList) == 0 {
		return nil // upsd running with no UPS configured
	}
	// "UPS <name> "<description>"": the first UPS is the one on this NAS.
	f := strings.Fields(upsList[0])
	if len(f) < 2 || f[0] != "UPS" {
		return fmt.Errorf("unexpected upsd reply %q", upsList[0])
	}
	name := f[1]

	vars := map[string]string{}
	varLines, err := ask("LIST VAR " + name)
	if err != nil {
		// DATA-STALE or DRIVER-NOT-CONNECTED: the UPS stopped answering
		// over USB. Report that, not a battery state nobody can know.
		e.gauge("synology_ups_reachable", 0, nil)
		return nil
	}
	for _, line := range varLines {
		// VAR <ups> <key> "<value>"
		parts := strings.SplitN(line, " ", 4)
		if len(parts) == 4 && parts[0] == "VAR" {
			vars[parts[2]] = strings.Trim(parts[3], `"`)
		}
	}
	_, _ = conn.Write([]byte("LOGOUT\n"))

	status, ok := vars["ups.status"]
	e.gauge("synology_ups_reachable", b2f(ok), nil)
	if !ok {
		return nil
	}
	flags := map[string]bool{}
	for _, fl := range strings.Fields(status) {
		flags[fl] = true
	}
	e.gauge("synology_ups_on_battery", b2f(flags["OB"]), nil)
	e.gauge("synology_ups_low_battery", b2f(flags["LB"]), nil)
	e.gauge("synology_ups_replace_battery", b2f(flags["RB"]), nil)
	for key, metric := range map[string]string{
		"battery.charge":  "synology_ups_battery_charge_percent",
		"battery.runtime": "synology_ups_runtime_seconds",
		"ups.load":        "synology_ups_load_percent",
	} {
		if v, err := strconv.ParseFloat(vars[key], 64); err == nil {
			e.gauge(metric, v, nil)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Snapshot Replication: /volumeN/@sharesnap/<share>/<snapshot>/, readable by
// any user. A share whose newest snapshot is older than its usual interval
// plus an hour has stopped being snapshotted: with immutable snapshots, that
// is how the clean copies age out unnoticed.
// ---------------------------------------------------------------------------

// snapshotGrace is how late a snapshot may be before the share counts as stale.
const snapshotGrace = time.Hour

// unknownInterval is assumed for a share with a single snapshot so far.
const unknownInterval = 25 * time.Hour

func (c *Collector) collectSnapshots(e *emitter) error {
	shares, err := sharesnap.Shares(c.volumes)
	if err != nil {
		return err
	}
	if len(shares) == 0 {
		return nil // Snapshot Replication not in use
	}
	stale := 0
	for _, s := range shares {
		age := e.ts.Sub(s.Snapshots[0].Time)
		interval := s.Interval()
		if interval == 0 {
			interval = unknownInterval
		}
		late := age > interval+snapshotGrace
		if late {
			stale++
		}
		labels := map[string]string{"share": s.Name}
		e.gauge("synology_snapshot_age_seconds", age.Seconds(), labels)
		e.gauge("synology_snapshot_interval_seconds", interval.Seconds(), labels)
		e.gauge("synology_snapshot_stale", b2f(late), labels)
		e.gauge("synology_snapshot_count", float64(len(s.Snapshots)), labels)
	}
	e.gauge("synology_snapshots_stale", float64(stale), nil)
	return nil
}
