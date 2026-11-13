package synology

import (
	"bufio"
	"context"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

var testNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// fixture copies testdata into a temporary root, applying edits (path
// relative to testdata, to replacer pairs; nil drops the file).
type fixture struct {
	root string
	c    *Collector
}

func newFixture(t *testing.T, edits map[string][]string) *fixture {
	t.Helper()
	root := t.TempDir()
	err := filepath.WalkDir("testdata", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("testdata", path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		if pairs, ok := edits[rel]; ok {
			if pairs == nil {
				return nil
			}
			text = strings.NewReplacer(pairs...).Replace(text)
		}
		dest := filepath.Join(root, rel)
		if strings.HasSuffix(rel, ".json") {
			dest = filepath.Join(root, "status", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dest, []byte(text), 0o644); err != nil {
			return err
		}
		mtime := testNow.Add(-2 * time.Minute)
		return os.Chtimes(dest, mtime, mtime)
	})
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "synoinfo.conf")
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewCollector("nas", WithStatusDir(filepath.Join(root, "status")))
	c.marker = marker
	c.mdstat = filepath.Join(root, "mdstat")
	c.mounts = filepath.Join(root, "mounts")
	c.disksDir = filepath.Join(root, "synostorage", "disks")
	c.hwmonDir = filepath.Join(root, "hwmon")
	c.upsAddr = "127.0.0.1:1"                  // nothing listens: no UPS
	c.volumes = filepath.Join(root, "volume*") // no snapshots unless a test makes some
	c.owner = uint32(os.Getuid())
	c.now = func() time.Time { return testNow }
	return &fixture{root: root, c: c}
}

type got map[string][]metrics.Metric

func collect(t *testing.T, c *Collector) got {
	t.Helper()
	ms, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	out := got{}
	for _, m := range ms {
		out[m.Name] = append(out[m.Name], m)
	}
	return out
}

// one returns the value of the only series of name whose labels include want.
func (g got) one(t *testing.T, name string, want map[string]string) float64 {
	t.Helper()
	var found []metrics.Metric
	for _, m := range g[name] {
		ok := true
		for k, v := range want {
			if m.Labels[k] != v {
				ok = false
			}
		}
		if ok {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s %v: want one series, got %d", name, want, len(found))
	}
	return found[0].Value
}

// fakeUPS answers the NUT protocol the way DSM's upsd does.
func fakeUPS(t *testing.T, vars map[string]string, listErr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					switch sc.Text() {
					case "LIST UPS":
						conn.Write([]byte("BEGIN LIST UPS\nUPS ups \"UPS on USB\"\nEND LIST UPS\n"))
					case "LIST VAR ups":
						if listErr != "" {
							conn.Write([]byte("ERR " + listErr + "\n"))
							continue
						}
						var b strings.Builder
						b.WriteString("BEGIN LIST VAR ups\n")
						for k, v := range vars {
							b.WriteString("VAR ups " + k + " \"" + v + "\"\n")
						}
						b.WriteString("END LIST VAR ups\n")
						conn.Write([]byte(b.String()))
					case "LOGOUT":
						conn.Write([]byte("OK Goodbye\n"))
						return
					default:
						conn.Write([]byte("ERR UNKNOWN-COMMAND\n"))
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

var onLine = map[string]string{"ups.status": "OL", "battery.charge": "100", "battery.runtime": "4107", "ups.load": "12"}

func TestHealthyNASWithoutStatusTask(t *testing.T) {
	f := newFixture(t, map[string][]string{
		"security_scan.json": nil, "upgrade.json": nil, "login_activity.json": nil, "containers.json": nil,
	})
	f.c.upsAddr = fakeUPS(t, onLine, "")
	g := collect(t, f.c)
	for _, c := range []struct {
		name   string
		labels map[string]string
		want   float64
	}{
		{"synology_status_present", nil, 0},
		{"synology_disk_healthy", map[string]string{"disk": "Drive 2", "id": "sata1"}, 1},
		{"synology_disk_temperature_celsius", map[string]string{"disk": "Drive 2"}, 31},
		{"synology_disk_remaining_life_percent", map[string]string{"disk": "Drive 1"}, 97},
		{"synology_disks_unhealthy", nil, 0},
		{"synology_disks_missing", nil, 0},
		{"synology_disk_max_temperature_celsius", nil, 31},
		{"synology_disk_min_remaining_life_percent", nil, 96},
		{"synology_md_arrays_degraded", nil, 0},
		{"synology_volume_healthy", map[string]string{"volume": "/volume1"}, 1},
		{"synology_volumes_unhealthy", nil, 0},
		{"synology_system_temperature_celsius", nil, 45},
		{"synology_ups_reachable", nil, 1},
		{"synology_ups_on_battery", nil, 0},
		{"synology_ups_battery_charge_percent", nil, 100},
		{"synology_ups_runtime_seconds", nil, 4107},
	} {
		if v := g.one(t, c.name, c.labels); v != c.want {
			t.Errorf("%s %v = %v, want %v", c.name, c.labels, v, c.want)
		}
	}
	// What only the status task can provide is absent, not zero.
	for _, name := range []string{"synology_security_scan_safe", "synology_update_available", "synology_abnormal_logins_new", "synology_containers_stopped", "synology_status_age_seconds"} {
		if len(g[name]) != 0 {
			t.Errorf("%s reported without the status task", name)
		}
	}
	for _, m := range g["synology_disk_healthy"] {
		if _, ok := m.Labels["serial"]; ok {
			t.Errorf("disk labels carry a serial: %v", m.Labels)
		}
	}
}

func TestFailingDisk(t *testing.T) {
	f := newFixture(t, map[string][]string{
		"synostorage/disks/sata2/smart":      {"normal", "abnormal"},
		"synostorage/disks/sata2/unc_status": {"normal", "warning"},
		"synostorage/disks/sata2/bad_sec_ct": {"-1", "12"},
	})
	g := collect(t, f.c)
	if v := g.one(t, "synology_disk_healthy", map[string]string{"disk": "Drive 1", "smart": "abnormal", "status": "unc_status warning, bad sectors"}); v != 0 {
		t.Errorf("failing disk reported healthy")
	}
	if v := g.one(t, "synology_disk_bad_sectors", map[string]string{"disk": "Drive 1"}); v != 12 {
		t.Errorf("bad sectors = %v", v)
	}
	if v := g.one(t, "synology_disks_unhealthy", nil); v != 1 {
		t.Errorf("disks_unhealthy = %v", v)
	}
}

func TestWornAndHotDisk(t *testing.T) {
	f := newFixture(t, map[string][]string{
		"synostorage/disks/sata2/temperature":        {"28", "63"},
		"synostorage/disks/sata2/remain_life":        {"97", "4"},
		"synostorage/disks/sata2/remain_life_danger": {"0", "1"},
	})
	g := collect(t, f.c)
	if v := g.one(t, "synology_disk_min_remaining_life_percent", nil); v != 4 {
		t.Errorf("min life = %v", v)
	}
	if v := g.one(t, "synology_disk_max_temperature_celsius", nil); v != 63 {
		t.Errorf("max temp = %v", v)
	}
	// DSM's own verdict that the wear is dangerous makes the disk unhealthy.
	if v := g.one(t, "synology_disks_unhealthy", nil); v != 1 {
		t.Errorf("disks_unhealthy = %v", v)
	}
}

func TestNoLifeValueOnAHardDisk(t *testing.T) {
	f := newFixture(t, map[string][]string{"synostorage/disks/sata2/remain_life": {"97", "-1"}})
	g := collect(t, f.c)
	if len(g["synology_disk_remaining_life_percent"]) != 1 {
		t.Errorf("a -1 life value was reported: %v", g["synology_disk_remaining_life_percent"])
	}
}

func TestPulledDiskDegradesRAID(t *testing.T) {
	// Drive 1 (sata2) pulled: DSM drops its directory, every array runs on one member.
	f := newFixture(t, map[string][]string{
		"mdstat": {"[2/2] [UU]", "[2/1] [U_]"},
	})
	if err := os.RemoveAll(filepath.Join(f.c.disksDir, "sata2")); err != nil {
		t.Fatal(err)
	}
	g := collect(t, f.c)
	if v := g.one(t, "synology_md_arrays_degraded", nil); v != 4 {
		t.Errorf("md_arrays_degraded = %v", v)
	}
	if v := g.one(t, "synology_md_degraded", map[string]string{"array": "md2"}); v != 1 {
		t.Errorf("md2 not degraded")
	}
	if v := g.one(t, "synology_disks_missing", nil); v != 1 {
		t.Errorf("disks_missing = %v", v)
	}
}

func TestVolumeRemountedReadOnly(t *testing.T) {
	f := newFixture(t, map[string][]string{
		"mounts": {"/volume1 btrfs rw,nodev", "/volume1 btrfs ro,nodev"},
	})
	g := collect(t, f.c)
	if v := g.one(t, "synology_volume_healthy", map[string]string{"volume": "/volume1", "status": "read-only"}); v != 0 {
		t.Errorf("read-only volume reported healthy")
	}
	if v := g.one(t, "synology_volumes_unhealthy", nil); v != 1 {
		t.Errorf("volumes_unhealthy = %v", v)
	}
}

func TestUPSOnBattery(t *testing.T) {
	f := newFixture(t, nil)
	f.c.upsAddr = fakeUPS(t, map[string]string{"ups.status": "OB DISCHRG LB", "battery.charge": "8", "battery.runtime": "300"}, "")
	g := collect(t, f.c)
	for name, want := range map[string]float64{
		"synology_ups_on_battery":             1,
		"synology_ups_low_battery":            1,
		"synology_ups_battery_charge_percent": 8,
	} {
		if v := g.one(t, name, nil); v != want {
			t.Errorf("%s = %v, want %v", name, v, want)
		}
	}
}

func TestUPSStale(t *testing.T) {
	f := newFixture(t, nil)
	f.c.upsAddr = fakeUPS(t, nil, "DATA-STALE")
	g := collect(t, f.c)
	if v := g.one(t, "synology_ups_reachable", nil); v != 0 {
		t.Errorf("stale UPS reported reachable")
	}
	if len(g["synology_ups_on_battery"]) != 0 {
		t.Errorf("a stale UPS reported a battery state")
	}
}

func TestNoUPSService(t *testing.T) {
	g := collect(t, newFixture(t, nil).c)
	if len(g["synology_ups_reachable"]) != 0 {
		t.Errorf("a NAS without a UPS service reported one")
	}
}

func TestStatusTaskFiles(t *testing.T) {
	f := newFixture(t, nil)
	g := collect(t, f.c)
	for name, want := range map[string]float64{
		"synology_status_present":         1,
		"synology_status_age_seconds":     120,
		"synology_security_scan_safe":     1,
		"synology_security_scan_findings": 0,
		"synology_update_available":       0,
		"synology_abnormal_logins_new":    0,
		"synology_containers_stopped":     0,
	} {
		if v := g.one(t, name, nil); v != want {
			t.Errorf("%s = %v, want %v", name, v, want)
		}
	}
	// The first read of sign-in history sets the baseline: old records are not news.
	if len(g["synology_abnormal_login"]) != 0 {
		t.Errorf("first read reported %d old sign-ins", len(g["synology_abnormal_login"]))
	}
}

func TestNewAbnormalSignIn(t *testing.T) {
	f := newFixture(t, nil)
	collect(t, f.c) // baseline
	path := filepath.Join(f.c.statusDir, "login_activity.json")
	data, _ := os.ReadFile(path)
	newer := strings.Replace(string(data), `"items":[`, `"items":[
 {"create_time":"2026/11/13 11:58:00","severity":"high","str_id":"abnormal_login","user":"alice","str_args":{"city":"Lisbon","country_code":"PT","ip":"198.51.100.7","protocol":"DSM","timestamp":"1794571080","user":"alice"}},`, 1)
	if err := os.WriteFile(path, []byte(newer), 0o644); err != nil {
		t.Fatal(err)
	}
	g := collect(t, f.c)
	if v := g.one(t, "synology_abnormal_logins_new", nil); v != 1 {
		t.Errorf("abnormal_logins_new = %v", v)
	}
	if v := g.one(t, "synology_abnormal_login", map[string]string{"user": "alice", "ip": "198.51.100.7", "country": "PT", "city": "Lisbon", "protocol": "DSM"}); v != 1 {
		t.Errorf("abnormal_login = %v", v)
	}
	g = collect(t, f.c)
	if v := g.one(t, "synology_abnormal_logins_new", nil); v != 0 {
		t.Errorf("the same sign-in was reported twice")
	}
}

func TestSecurityAdvisorFindingsAndUpdate(t *testing.T) {
	f := newFixture(t, map[string][]string{
		"security_scan.json": {`"network":{"category":"network","fail":{"danger":0,"info":0,"outOfDate":0,"risk":0,"warning":0},"failSeverity":"safe"}`, `"network":{"category":"network","fail":{"danger":1,"info":0,"outOfDate":0,"risk":2,"warning":3},"failSeverity":"danger"}`, `"sysStatus":"safe"`, `"sysStatus":"danger"`},
		"upgrade.json":       {`"available":false`, `"available":true,"version":"DSM 7.4.2-91000"`},
	})
	g := collect(t, f.c)
	if v := g.one(t, "synology_security_scan_safe", nil); v != 0 {
		t.Errorf("scan reported safe")
	}
	if v := g.one(t, "synology_security_scan_findings", nil); v != 6 {
		t.Errorf("findings = %v", v)
	}
	if v := g.one(t, "synology_security_scan_failing", map[string]string{"category": "network", "severity": "danger"}); v != 6 {
		t.Errorf("failing category = %v", v)
	}
	if v := g.one(t, "synology_update_available", nil); v != 1 {
		t.Errorf("update not reported")
	}
}

func TestStoppedContainer(t *testing.T) {
	f := newFixture(t, map[string][]string{
		"containers.json": {`{"name":"blog","status":"running"`, `{"name":"blog","status":"exited"`},
	})
	g := collect(t, f.c)
	if v := g.one(t, "synology_container_running", map[string]string{"container": "blog"}); v != 0 {
		t.Errorf("stopped container reported running")
	}
	if v := g.one(t, "synology_containers_stopped", nil); v != 1 {
		t.Errorf("containers_stopped = %v", v)
	}
}

func TestUntrustedStatusFileIsRefused(t *testing.T) {
	f := newFixture(t, nil)
	if err := os.Chmod(filepath.Join(f.c.statusDir, "security_scan.json"), 0o666); err != nil {
		t.Fatal(err)
	}
	g := collect(t, f.c)
	if len(g["synology_security_scan_safe"]) != 0 {
		t.Errorf("a world-writable status file was believed")
	}
}

func TestStaleStatusFileIsIgnored(t *testing.T) {
	f := newFixture(t, nil)
	old := testNow.Add(-45 * time.Minute)
	for _, name := range []string{"security_scan.json", "upgrade.json"} {
		if err := os.Chtimes(filepath.Join(f.c.statusDir, name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	g := collect(t, f.c)
	if len(g["synology_security_scan_safe"]) != 0 {
		t.Errorf("a 45-minute-old scan reply was reported as current")
	}
	// The update check runs hourly, so 45 minutes is fresh for it.
	if len(g["synology_update_available"]) != 1 {
		t.Errorf("a 45-minute-old update check was dropped")
	}
}

func TestEnabledOnlyOnDSM(t *testing.T) {
	f := newFixture(t, nil)
	if !f.c.Enabled() {
		t.Errorf("not enabled with the DSM marker present")
	}
	f.c.marker = filepath.Join(t.TempDir(), "nope")
	if f.c.Enabled() {
		t.Errorf("enabled without DSM")
	}
}

func TestSnapshotFreshness(t *testing.T) {
	f := newFixture(t, nil)
	vol := filepath.Join(f.root, "volume1")
	// homes: hourly, newest 40 minutes old. data: hourly, but the newest is
	// three hours old. Photos: daily, newest 20 hours old.
	for _, d := range []string{
		"homes/GMT+00-2026.11.13-11.20.00", "homes/GMT+00-2026.11.13-10.20.00", "homes/GMT+00-2026.11.13-09.20.00",
		"data/GMT+00-2026.11.13-09.00.00", "data/GMT+00-2026.11.13-08.00.00", "data/GMT+00-2026.11.13-07.00.00",
		"Photos/GMT+00-2026.11.12-16.00.00", "Photos/GMT+00-2026.11.11-16.00.00", "Photos/GMT+00-2026.11.10-16.00.00",
	} {
		if err := os.MkdirAll(filepath.Join(vol, "@sharesnap", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.c.volumes = filepath.Join(f.root, "volume*")
	g := collect(t, f.c)
	if v := g.one(t, "synology_snapshot_age_seconds", map[string]string{"share": "homes"}); v != 2400 {
		t.Errorf("homes age = %v", v)
	}
	for share, want := range map[string]float64{"homes": 0, "data": 1, "Photos": 0} {
		if v := g.one(t, "synology_snapshot_stale", map[string]string{"share": share}); v != want {
			t.Errorf("%s stale = %v, want %v", share, v, want)
		}
	}
	if v := g.one(t, "synology_snapshots_stale", nil); v != 1 {
		t.Errorf("snapshots_stale = %v", v)
	}
	if v := g.one(t, "synology_snapshot_interval_seconds", map[string]string{"share": "Photos"}); v != 86400 {
		t.Errorf("Photos interval = %v", v)
	}
}

func TestNoSnapshotsNoMetrics(t *testing.T) {
	f := newFixture(t, nil)
	f.c.volumes = filepath.Join(f.root, "nothing*")
	g := collect(t, f.c)
	if len(g["synology_snapshots_stale"]) != 0 {
		t.Errorf("snapshot metrics without Snapshot Replication")
	}
}
