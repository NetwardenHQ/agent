package opnsense

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

func find(ms []metrics.Metric, name string, labels map[string]string) (metrics.Metric, bool) {
outer:
	for _, m := range ms {
		if m.Name != name {
			continue
		}
		for k, v := range labels {
			if m.Labels[k] != v {
				continue outer
			}
		}
		return m, true
	}
	return metrics.Metric{}, false
}

func TestParseFirmware(t *testing.T) {
	data := []byte(`{"api_version":"2","connection":"ok","downgrade_packages":[],"download_size":"12MiB","last_check":"Sat Oct 17 10:00:00 EDT 2026","needs_reboot":"1","new_packages":[{"name":"os-x","version":"1.0"}],"os_version":"FreeBSD 15.1","product_id":"opnsense","product_target":"opnsense","product_version":"26.7.7","product_abi":"26.7","reinstall_packages":[],"remove_packages":[],"repository":"ok","upgrade_major_message":"","upgrade_major_version":"","upgrade_needs_reboot":"0","upgrade_packages":[{"name":"a","current_version":"1","new_version":"2"},{"name":"b","current_version":"1","new_version":"2"}],"upgrade_sets":[]}`)
	f, err := parseFirmware(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Upgrade) != 2 || len(f.NewPackages) != 1 || f.NeedsReboot != "1" || f.ProductVersion != "26.7.7" {
		t.Fatalf("unexpected parse: %+v", f)
	}
	if _, err := parseFirmware([]byte(`{"x":1}`)); err == nil {
		t.Fatal("a status file without connection/repository must be rejected")
	}
	if _, err := parseFirmware([]byte(`not json`)); err == nil {
		t.Fatal("invalid JSON must be rejected")
	}
}

func TestFirmwareMetricsRequireReachableMirror(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pkg_upgrade.json")
	os.WriteFile(p, []byte(`{"connection":"unresolved","repository":"error","needs_reboot":"0","product_id":"opnsense","product_version":"26.7","upgrade_packages":[],"upgrade_sets":[]}`), 0o600)
	c := NewCollector("fw")
	c.firmwareJSON = p
	c.firmwareOwner = uint32(os.Getuid())
	e := &emitter{c: c, ts: time.Now()}
	if err := c.collectFirmware(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if m, _ := find(e.out, "opnsense_firmware_check_ok", nil); m.Value != 0 {
		t.Fatal("unreachable mirror must report check_ok=0")
	}
	if _, ok := find(e.out, "opnsense_firmware_upgrade_packages", nil); ok {
		t.Fatal("package counts must not be reported when the check failed (an empty list would read as 'up to date')")
	}
}

func TestFirmwareMissingFileIsError(t *testing.T) {
	c := NewCollector("fw")
	c.firmwareJSON = filepath.Join(t.TempDir(), "absent.json")
	if err := c.collectFirmware(context.Background(), &emitter{c: c, ts: time.Now()}); err == nil {
		t.Fatal("a missing status file must be an error, not zero updates")
	}
}

func TestGateways(t *testing.T) {
	data := []byte(`{"WAN_DHCP":{"name":"WAN_DHCP","address":"203.0.113.1","status":"none","loss":"0.0 %","delay":"8.4 ms","stddev":"0.6 ms","monitor":"203.0.113.1"},
"BACKUP":{"name":"BACKUP","address":"198.51.100.1","status":"down","loss":"100.0 %","delay":"~","stddev":"~","monitor":"198.51.100.1"},
"LTE":{"name":"LTE","address":"~","status":"none","loss":"~","delay":"~","stddev":"~","monitor":"~"},
"SLOW":{"name":"SLOW","address":"192.0.2.1","status":"delay+loss","loss":"8.0 %","delay":"340.2 ms","stddev":"40.0 ms","monitor":"192.0.2.1"}}`)
	gws, err := parseGateways(data)
	if err != nil || len(gws) != 4 {
		t.Fatalf("parse: %v %d", err, len(gws))
	}
	c := NewCollector("fw")
	c.run = func(context.Context, string, ...string) ([]byte, error) { return data, nil }
	e := &emitter{c: c, ts: time.Now()}
	if err := c.collectGateways(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if m, ok := find(e.out, "opnsense_gateway_up", map[string]string{"gateway": "WAN_DHCP"}); !ok || m.Value != 1 {
		t.Fatal("WAN_DHCP should be up")
	}
	if m, ok := find(e.out, "opnsense_gateway_up", map[string]string{"gateway": "BACKUP"}); !ok || m.Value != 0 {
		t.Fatal("BACKUP should be down")
	}
	if _, ok := find(e.out, "opnsense_gateway_up", map[string]string{"gateway": "LTE"}); ok {
		t.Fatal("a gateway dpinger has no data for must not be reported up or down")
	}
	if m, ok := find(e.out, "opnsense_gateway_degraded", map[string]string{"gateway": "SLOW"}); !ok || m.Value != 1 {
		t.Fatal("SLOW should be degraded")
	}
	if m, _ := find(e.out, "opnsense_gateway_latency_ms", map[string]string{"gateway": "WAN_DHCP"}); m.Value != 8.4 {
		t.Fatalf("latency = %v", m.Value)
	}
	if _, ok := find(e.out, "opnsense_gateway_latency_ms", map[string]string{"gateway": "BACKUP"}); ok {
		t.Fatal("'~' latency must not become a number")
	}
}

const pfInfoOut = `Status: Enabled for 12 days 03:11:09             Debug: Urgent

State Table                          Total             Rate
  current entries                    54321
  searches                       987654321         9.1/s
  inserts                         12345678         1.0/s
  removals                        12291357         1.0/s
Counters
  match                           23456789         2.0/s
  bad-offset                             0         0.0/s
  state-limit                            7         0.0/s
`

func TestPF(t *testing.T) {
	info, err := parsePFInfo(pfInfoOut)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Enabled || info.Counters["current entries"] != 54321 || info.PacketCounters["state-limit"] != 7 {
		t.Fatalf("%+v", info)
	}
	if v, ok := parsePFStateLimit("states        hard limit  1000000\nsrc-nodes     hard limit  1000000\n"); !ok || v != 1000000 {
		t.Fatal("state limit")
	}
	if _, err := parsePFInfo("pfctl: /dev/pf: Permission denied"); err == nil {
		t.Fatal("garbage must be an error")
	}
	c := NewCollector("fw")
	c.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "-sm" {
			return []byte("states        hard limit  1000000\n"), nil
		}
		return []byte(pfInfoOut), nil
	}
	e := &emitter{c: c, ts: time.Now()}
	if err := c.collectPF(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if m, _ := find(e.out, "opnsense_pf_state_usage_percent", nil); m.Value < 5.43 || m.Value > 5.44 {
		t.Fatalf("usage = %v", m.Value)
	}
}

func TestCARP(t *testing.T) {
	out := "igc0: flags=1008843<UP>\n\tcarp: MASTER vhid 1 advbase 1 advskew 0\n\tcarp: BACKUP vhid 2 advbase 1 advskew 100\n"
	c := countCARP(out)
	if c["master"] != 1 || c["backup"] != 1 {
		t.Fatalf("%v", c)
	}
	if len(countCARP("igc0: flags=1008843<UP>\n")) != 0 {
		t.Fatal("no CARP must give no counts")
	}
}

const (
	v4block = `<134>1 2026-10-17T10:00:01-04:00 fw.lan filterlog 77 - [meta sequenceId="9"] 82,,,0b1f,igc0,match,block,in,4,0x0,,64,1234,0,none,6,tcp,60,198.51.100.7,203.0.113.5,51000,22,0,S,1,,64240,,mss`
	v4pass  = `<134>1 2026-10-17T10:00:02-04:00 fw.lan filterlog 77 - [meta sequenceId="10"] 12,,,aa11,igc1,match,pass,out,4,0x0,,64,99,0,none,17,udp,60,192.0.2.5,1.1.1.1,40000,53,40`
	v6block = `<134>1 2026-10-17T10:00:03-04:00 fw.lan filterlog 77 - [meta sequenceId="11"] 90,,,cc22,igc0,match,block,in,6,0x00,0x00000,255,tcp,6,40,2001:db8::7,2001:db8::1,50000,443,0,S,1,,1,`
)

func TestFilterLog(t *testing.T) {
	ev, ok := parseFilterLog([]byte(v4block))
	if !ok || ev.Interface != "igc0" || ev.Action != "block" || ev.Direction != "in" || ev.Src != "198.51.100.7" || ev.DstPort != "22" {
		t.Fatalf("v4: %+v %v", ev, ok)
	}
	ev, ok = parseFilterLog([]byte(v6block))
	if !ok || ev.Src != "2001:db8::7" || ev.DstPort != "443" {
		t.Fatalf("v6: %+v %v", ev, ok)
	}
	if _, ok := parseFilterLog([]byte("<30>1 2026-10-17T10:00:00-04:00 fw dhcpd 1 - - lease")); ok {
		t.Fatal("non filterlog line accepted")
	}
	tl := tallyLines(newFilterTally(), [][]byte{[]byte(v4block), []byte(v4block), []byte(v4pass), []byte(v6block), []byte("garbage")})
	if tl.blocked["igc0"] != 3 || tl.passed["igc1"] != 1 || tl.blockedSrc["198.51.100.7"] != 2 || tl.blockedPort["22"] != 2 {
		t.Fatalf("%+v", tl)
	}
	if top := topN(tl.blockedSrc, 1); top[0].Key != "198.51.100.7" || top[0].Count != 2 {
		t.Fatalf("%v", top)
	}
}

func TestAuth(t *testing.T) {
	lines := [][]byte{
		[]byte(`<37>1 2026-10-17T10:00:00-04:00 fw audit 5 - [meta sequenceId="1"] /index.php: Web GUI authentication error for 'root' from 198.51.100.9`),
		[]byte(`<37>1 2026-10-17T10:00:01-04:00 fw audit 5 - [meta sequenceId="2"] /index.php: Successful login for user 'root' from: 192.0.2.5`),
		[]byte(`<38>1 2026-10-17T10:00:02-04:00 fw sshd 6 - [meta sequenceId="3"] Failed password for invalid user admin from 198.51.100.9 port 4000 ssh2`),
		[]byte(`<38>1 2026-10-17T10:00:02-04:00 fw sshd 6 - [meta sequenceId="4"] Invalid user admin from 198.51.100.9 port 4000`),
		[]byte(`<38>1 2026-10-17T10:00:03-04:00 fw sshd 6 - [meta sequenceId="5"] Accepted publickey for root from 192.0.2.5 port 5000 ssh2`),
	}
	a := tallyLines(newAuthTally(), lines)
	if a.failGUI != 1 || a.failSSH != 1 || a.okGUI != 1 || a.okSSH != 1 {
		t.Fatalf("%+v", a)
	}
	if len(a.ips) != 1 || a.ips["198.51.100.9"] != 2 || len(a.users) != 2 {
		t.Fatalf("ips/users: %+v", a)
	}
}

// The username is attacker-chosen. Neither the reported address nor the
// classification of a line may depend on what an attacker typed into it.
func TestAuthResistsSpoofedUsernames(t *testing.T) {
	lines := [][]byte{
		// SSH user "x from 192.0.2.66": the real peer is the last address.
		[]byte(`<38>1 2026-10-17T10:00:02-04:00 fw sshd 6 - - Failed password for invalid user x from 192.0.2.66 from 198.51.100.9 port 4000 ssh2`),
		// GUI user "x' from 192.0.2.66 'y".
		[]byte(`<37>1 2026-10-17T10:00:00-04:00 fw audit 5 - - /index.php: Web GUI authentication error for 'x' from 192.0.2.66 'y' from 198.51.100.9`),
		// An SSH username that mentions the GUI must still count as SSH.
		[]byte(`<38>1 2026-10-17T10:00:03-04:00 fw sshd 6 - - Failed password for invalid user Web GUI authentication error for 'a' from 198.51.100.10 port 4001 ssh2`),
		// Not an address: counted as a failure, never as an IP label.
		[]byte(`<37>1 2026-10-17T10:00:04-04:00 fw audit 5 - - /index.php: Web GUI authentication error for 'root' from not-an-ip`),
		// Another program's line that merely mentions sshd.
		[]byte(`<13>1 2026-10-17T10:00:05-04:00 fw logger 7 - - Failed password for root from 192.0.2.77 port 1 ssh2 sshd`),
	}
	a := tallyLines(newAuthTally(), lines)
	if a.failSSH != 2 || a.failGUI != 2 {
		t.Fatalf("counts: %+v", a)
	}
	if a.ips["192.0.2.66"] != 0 || a.ips["192.0.2.77"] != 0 || a.ips["198.51.100.9"] != 2 || a.ips["198.51.100.10"] != 1 || len(a.ips) != 2 {
		t.Fatalf("ips: %v", a.ips)
	}
}

func TestSplitSyslog(t *testing.T) {
	cases := []struct{ line, app, msg string }{
		{`<134>1 2026-10-17T10:00:00-04:00 fw filterlog 123 - [meta sequenceId="1"] 5,,,a`, "filterlog", "5,,,a"},
		{`<134>1 2026-10-17T10:00:00-04:00 fw filterlog 123 - - 5,,,a`, "filterlog", "5,,,a"},
		{`<134>1 2026-10-17T10:00:00-04:00 fw app 1 - [a x="q\"]] "][b y="2"] hello`, "app", "hello"},
		{`<38>Oct  7 10:00:00 fw sshd[42]: Failed password`, "sshd", "Failed password"},
	}
	for _, c := range cases {
		app, msg, ok := splitSyslog([]byte(c.line))
		if !ok || string(app) != c.app || string(msg) != c.msg {
			t.Errorf("%q: got %q %q %v", c.line, app, msg, ok)
		}
	}
	for _, bad := range []string{"", "plain text", `<134>1 only three fields`, `<134>1 a b c d e [unterminated`} {
		if _, _, ok := splitSyslog([]byte(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEve(t *testing.T) {
	lines := [][]byte{
		[]byte(`{"timestamp":"2026-10-17T10:00:00.1-0400","event_type":"alert","src_ip":"198.51.100.7","alert":{"action":"blocked","signature_id":2024897,"signature":"ET SCAN Nmap","category":"Attempted Information Leak","severity":2}}`),
		[]byte(`{"timestamp":"2026-10-17T10:00:00.2-0400","event_type":"alert","src_ip":"198.51.100.7","alert":{"action":"allowed","signature_id":2024897,"signature":"ET SCAN Nmap","category":"Attempted Information Leak","severity":2}}`),
		[]byte(`{"timestamp":"2026-10-17T10:00:00.3-0400","event_type":"alert","src_ip":"203.0.113.2","alert":{"action":"allowed","signature_id":1,"signature":"X","severity":1}}`),
		[]byte(`{"event_type":"stats","stats":{"capture":{"kernel_packets":1000,"kernel_drops":4},"decoder":{"pkts":1000}}}`),
		[]byte(`{"event_type":"dns","dns":{}}`),
		[]byte(`{broken`),
	}
	tl := tallyLines(newIDSTally(), lines)
	if tl.alerts != 3 || tl.blocked != 1 || tl.bySeverity["2"] != 2 || tl.bySeverity["1"] != 1 || len(tl.srcs) != 2 || tl.bad != 1 {
		t.Fatalf("%+v", tl)
	}
	if tl.stats == nil || tl.stats.Stats.Capture.KernelDrops == nil || *tl.stats.Stats.Capture.KernelDrops != 4 {
		t.Fatalf("stats: %+v", tl.stats)
	}
}

const configFixture = `<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><user><name>root</name><password>$2y$secret</password></user></system>
  <OPNsense><IDS version="1.1.0"><general><enabled>1</enabled><ips>1</ips></general></IDS></OPNsense>
  <revision><username>root@192.0.2.5</username><time>1760712345.25</time><description>/ui/firewall/filter/set_rule.php made changes</description></revision>
</opnsense>`

func TestEveStatsWithoutCaptureEmitsNoCounters(t *testing.T) {
	tl := tallyLines(newIDSTally(), [][]byte{[]byte(`{"event_type":"stats","stats":{"decoder":{"pkts":1000}}}`)})
	if tl.stats == nil {
		t.Fatal("stats record not kept")
	}
	if tl.stats.Stats.Capture.KernelPackets != nil || tl.stats.Stats.Capture.KernelDrops != nil {
		t.Fatal("absent capture counters must stay absent, not 0")
	}
}

func TestConfigReadsOnlyWantedElements(t *testing.T) {
	for _, secret := range [][]string{
		{"opnsense", "system", "user", "password"},
		{"opnsense", "cert", "prv"},
		{"opnsense", "OPNsense", "wireguard", "server", "servers", "server", "privkey"},
		{"opnsense", "interfaces", "wan", "ipaddr"},
	} {
		if wantedConfigPath(secret) {
			t.Errorf("%v would be buffered", secret)
		}
	}
	xmlDoc := `<opnsense><OPNsense><OpenVPN><Instances><Instance><enabled>1</enabled></Instance></Instances></OpenVPN></OPNsense></opnsense>`
	info, err := parseConfig(strings.NewReader(xmlDoc))
	if err != nil || !info.VPN {
		t.Fatalf("MVC OpenVPN instance not detected: %+v %v", info, err)
	}
}

func TestConfig(t *testing.T) {
	info, err := parseConfig(strings.NewReader(configFixture))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IDSEnabled || !info.IPSMode || !info.HasRevision || info.RevisionTime.Unix() != 1760712345 || info.RevisionUser != "root@192.0.2.5" {
		t.Fatalf("%+v", info)
	}
	if _, err := parseConfig(strings.NewReader("<opnsense><unclosed>")); err == nil {
		t.Fatal("broken XML must be an error")
	}
}

func TestTailerBaselineAppendRotateAndPartialLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "eve.json")
	os.WriteFile(p, []byte("old1\nold2\n"), 0o600)
	tl := newTailer(func(time.Time) string { return p })
	now := time.Now()

	if _, _, measured, err := readLines(tl, now); err != nil || measured {
		t.Fatalf("first read must only set the baseline (measured=%v err=%v)", measured, err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("new1\nnew2\nhalf")
	lines, _, measured, _ := readLines(tl, now)
	if !measured || len(lines) != 2 || string(lines[1]) != "new2" {
		t.Fatalf("append: %q measured=%v", lines, measured)
	}
	f.WriteString("-done\n")
	f.Close()
	lines, _, _, _ = readLines(tl, now)
	if len(lines) != 1 || string(lines[0]) != "half-done" {
		t.Fatalf("partial line: %q", lines)
	}
	// Rotate: move the file away and create a shorter one.
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte("r1\n"), 0o600)
	lines, _, _, _ = readLines(tl, now)
	if len(lines) != 1 || string(lines[0]) != "r1" {
		t.Fatalf("rotate: %q", lines)
	}
}

func TestTailerDayRollover(t *testing.T) {
	dir := t.TempDir()
	d1 := time.Date(2026, 10, 17, 23, 59, 0, 0, time.UTC)
	d2 := d1.Add(2 * time.Minute)
	p1 := dailyLog(dir, "filter", d1)
	os.WriteFile(p1, []byte("a\n"), 0o600)
	tl := newTailer(func(t time.Time) string { return dailyLog(dir, "filter", t) })
	readLines(tl, d1)
	f, _ := os.OpenFile(p1, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("late\n")
	f.Close()
	os.WriteFile(dailyLog(dir, "filter", d2), []byte("first-of-day\n"), 0o600)
	lines, _, _, err := readLines(tl, d2)
	if err != nil || len(lines) != 2 || string(lines[0]) != "late" || string(lines[1]) != "first-of-day" {
		t.Fatalf("rollover: %q %v", lines, err)
	}
	// syslog-ng may still write to yesterday's file after midnight.
	f, _ = os.OpenFile(p1, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("later\n")
	f.Close()
	lines, _, _, _ = readLines(tl, d2.Add(time.Minute))
	if len(lines) != 1 || string(lines[0]) != "later" {
		t.Fatalf("late write to old file: %q", lines)
	}
	// After the grace period the old file is no longer read.
	f, _ = os.OpenFile(p1, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("too-late\n")
	f.Close()
	readLines(tl, d2.Add(rolloverGrace+time.Minute))
	f, _ = os.OpenFile(p1, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("ignored\n")
	f.Close()
	if lines, _, _, _ = readLines(tl, d2.Add(rolloverGrace+2*time.Minute)); len(lines) != 0 {
		t.Fatalf("old file still read after grace: %q", lines)
	}
}

func TestTailerSkipsOverlongLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(p, nil, 0o600)
	tl := newTailer(func(time.Time) string { return p })
	readLines(tl, time.Now())
	long := strings.Repeat("A", maxLineBytes*2)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("ok1\n" + long + "\nok2\n" + long[:maxLineBytes+10]) // last one unfinished
	f.Close()
	lines, skipped, _, err := readLines(tl, time.Now())
	if err != nil || len(lines) != 2 || string(lines[0]) != "ok1" || string(lines[1]) != "ok2" || skipped < int64(len(long)) {
		t.Fatalf("lines %d skipped %d err %v", len(lines), skipped, err)
	}
	// The unfinished over-long line completes: still dropped whole.
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("tail\nok3\n")
	f.Close()
	lines, _, _, _ = readLines(tl, time.Now())
	if len(lines) != 1 || string(lines[0]) != "ok3" {
		t.Fatalf("after long line: %q", lines)
	}
}

func TestTailerMissingLogIsNotMeasured(t *testing.T) {
	tl := newTailer(func(time.Time) string { return filepath.Join(t.TempDir(), "never") })
	for i := 0; i < 2; i++ {
		if _, _, measured, err := readLines(tl, time.Now()); err != nil || measured {
			t.Fatalf("a log that never existed must not yield a measurement (measured=%v err=%v)", measured, err)
		}
	}
}

func TestEnabledOnlyOnOPNsense(t *testing.T) {
	c := NewCollector("fw")
	c.versionMarker = filepath.Join(t.TempDir(), "absent")
	if c.Enabled() {
		t.Fatal("must be disabled without OPNsense markers")
	}
}

func TestCollectEndToEndWithFixtures(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c := NewCollector("fw", WithLogger(slog.New(slog.NewTextHandler(os.Stderr, nil))))
	c.now = func() time.Time { return now }
	c.configXML = filepath.Join(dir, "config.xml")
	c.backupDir = filepath.Join(dir, "backup")
	c.firmwareJSON = filepath.Join(dir, "pkg_upgrade.json")
	c.firmwareOwner = uint32(os.Getuid())
	c.eveJSON = filepath.Join(dir, "eve.json")
	c.suricataPID = filepath.Join(dir, "suricata.pid")
	c.filterLogDir = dir
	c.auditLogDir = dir
	os.Mkdir(c.backupDir, 0o700)
	os.WriteFile(filepath.Join(c.backupDir, "config-1.xml"), nil, 0o600)
	os.WriteFile(c.configXML, []byte(configFixture), 0o600)
	os.WriteFile(c.firmwareJSON, []byte(`{"connection":"ok","repository":"ok","needs_reboot":"0","product_id":"opnsense","product_version":"26.7.7","upgrade_packages":[{"name":"a"}],"upgrade_sets":[]}`), 0o600)
	os.WriteFile(c.suricataPID, []byte(fmt.Sprint(os.Getpid())), 0o600)
	os.WriteFile(c.eveJSON, nil, 0o600)
	fl := dailyLog(dir, "filter", now)
	al := dailyLog(dir, "audit", now)
	os.WriteFile(fl, nil, 0o600)
	os.WriteFile(al, nil, 0o600)
	c.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch {
		case strings.HasSuffix(name, "configctl"):
			return []byte(`{"WAN":{"name":"WAN","address":"203.0.113.1","status":"none","loss":"0.0 %","delay":"8.4 ms","stddev":"0.6 ms"}}`), nil
		case strings.HasSuffix(name, "pfctl") && args[0] == "-si":
			return []byte(pfInfoOut), nil
		case strings.HasSuffix(name, "pfctl"):
			return []byte("states hard limit 1000000\n"), nil
		case strings.HasSuffix(name, "ifconfig"):
			return []byte("igc0: flags=1\n"), nil
		}
		return nil, fmt.Errorf("unexpected command %s", name)
	}

	first, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The first cycle has no log interval yet: no filter/audit/IDS counts.
	for _, name := range []string{"opnsense_filter_blocked_total_interval", "security_failed_logins", "opnsense_ids_alerts"} {
		if _, ok := find(first, name, nil); ok {
			t.Fatalf("%s must not be emitted on the baseline cycle", name)
		}
	}
	if m, ok := find(first, "opnsense_ids_running", nil); !ok || m.Value != 1 {
		t.Fatal("ids running")
	}
	if m, ok := find(first, "opnsense_config_backups", nil); !ok || m.Value != 1 {
		t.Fatal("backups")
	}

	appendTo := func(path, s string) {
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		f.WriteString(s)
		f.Close()
	}
	appendTo(fl, v4block+"\n"+v4pass+"\n")
	appendTo(al, `<37>1 2026-10-17T10:00:00-04:00 fw audit 5 - [meta sequenceId="1"] /index.php: Web GUI authentication error for 'root' from 198.51.100.9`+"\n")
	appendTo(c.eveJSON, `{"event_type":"alert","src_ip":"198.51.100.7","alert":{"action":"blocked","signature_id":1,"signature":"S","severity":1}}`+"\n")

	second, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := find(second, "opnsense_filter_blocked_total_interval", nil); !ok || m.Value != 1 {
		t.Fatalf("blocked: %v %v", m, ok)
	}
	if m, ok := find(second, "security_failed_logins", nil); !ok || m.Value != 1 {
		t.Fatal("failed logins")
	}
	if m, ok := find(second, "opnsense_ids_blocked", nil); !ok || m.Value != 1 {
		t.Fatal("ids blocked")
	}
	third, _ := c.Collect(context.Background())
	if m, _ := find(third, "opnsense_filter_blocked_total_interval", nil); m.Value != 0 {
		t.Fatal("an idle interval must report 0, and must not replay old lines")
	}
}

const identityConfigFixture = `<?xml version="1.0"?>
<opnsense>
  <system><user><name>root</name><password>$2y$secret</password><apikeys><item><key>KEY</key><secret>SECRET</secret></item></apikeys></user></system>
  <interfaces>
    <wan><if>em0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><if>em1</if><ipaddr>192.0.2.1</ipaddr></lan>
    <opt1><if>em2_vlan10</if></opt1>
    <opt2><if>wg0</if></opt2>
    <opt3><if>ovpns1</if></opt3>
    <wireguard><if>wg1</if></wireguard>
    <guest><if>em3</if></guest>
  </interfaces>
  <dhcpd><lan><enable>1</enable></lan></dhcpd>
  <OPNsense>
    <IDS><general><enabled>1</enabled></general></IDS>
    <wireguard><general><enabled>1</enabled></general></wireguard>
    <unboundplus><general><enabled>1</enabled></general></unboundplus>
  </OPNsense>
</opnsense>`

func TestInterfaceRoleFromConfig(t *testing.T) {
	info, err := parseConfig(strings.NewReader(identityConfigFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"wan": "wan", "lan": "lan", "opt1": "lan", "opt2": "vpn", "opt3": "vpn", "wireguard": "vpn", "guest": "other"}
	for logical, role := range want {
		if got := interfaceRole(logical, info.Interfaces[logical]); got != role {
			t.Errorf("%s (%s): got %s want %s", logical, info.Interfaces[logical], got, role)
		}
	}
	if !info.VPN || !info.DHCP || !info.DNS || !info.IDSEnabled {
		t.Fatalf("%+v", info)
	}
}

func TestIdentityFromFixtures(t *testing.T) {
	dir := t.TempDir()
	c := NewCollector("fw")
	c.configXML = filepath.Join(dir, "config.xml")
	c.versionMarker = filepath.Join(dir, "core")
	c.crowdsecBin = filepath.Join(dir, "cscli")
	c.crowdsecCfg = filepath.Join(dir, "crowdsec.yaml")
	os.WriteFile(c.configXML, []byte(identityConfigFixture), 0o600)
	os.WriteFile(c.versionMarker, []byte(`{"product_name":"OPNsense","product_version":"26.7.7"}`), 0o600)

	id, err := c.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if id.Version != "26.7.7" {
		t.Fatalf("version %q", id.Version)
	}
	if got := strings.Join(id.Capabilities, ","); got != "firewall,nat,ids,vpn,dhcp,dns" {
		t.Fatalf("capabilities %s (crowdsec must be absent without its files)", got)
	}
	if id.InterfaceRoles["em0"] != "wan" || id.InterfaceRoles["em1"] != "lan" || id.InterfaceRoles["wg0"] != "vpn" || id.InterfaceRoles["em3"] != "other" {
		t.Fatalf("%v", id.InterfaceRoles)
	}

	os.WriteFile(c.crowdsecBin, nil, 0o700)
	os.WriteFile(c.crowdsecCfg, nil, 0o600)
	id, _ = c.Identity()
	if !strings.HasSuffix(strings.Join(id.Capabilities, ","), ",crowdsec") {
		t.Fatalf("crowdsec present: %v", id.Capabilities)
	}

	// Config without optional services: only what is provable.
	os.WriteFile(c.configXML, []byte(`<opnsense><interfaces><wan><if>em0</if></wan></interfaces></opnsense>`), 0o600)
	os.Remove(c.crowdsecBin)
	id, _ = c.Identity()
	if got := strings.Join(id.Capabilities, ","); got != "firewall,nat" {
		t.Fatalf("got %s", got)
	}

	// Unreadable config: firewall+nat only, no roles, error reported.
	os.Remove(c.configXML)
	id, err = c.Identity()
	if err == nil || id.InterfaceRoles != nil || len(id.Capabilities) != 2 {
		t.Fatalf("%+v %v", id, err)
	}
}

// readLines collects what tailer.each streams, copying each line.
func readLines(t *tailer, now time.Time) ([][]byte, int64, bool, error) {
	var lines [][]byte
	skipped, measured, err := t.each(now, func(l []byte) { lines = append(lines, append([]byte(nil), l...)) })
	return lines, skipped, measured, err
}

func tallyLines[T interface{ add([]byte) }](t T, lines [][]byte) T {
	for _, l := range lines {
		t.add(l)
	}
	return t
}
