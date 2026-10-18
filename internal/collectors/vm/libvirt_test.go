//go:build linux

package vm

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/config"
)

const sampleDomStats = `Domain: 'web-1'
  state.state=1
  cpu.time=123456789000
  balloon.current=4194304
  balloon.maximum=8388608
  balloon.rss=2097152
  block.count=1
  block.0.name=vda
  block.0.rd.reqs=100
  block.0.rd.bytes=4096
  block.0.wr.reqs=50
  block.0.wr.bytes=8192
  net.count=1
  net.0.name=vnet0
  net.0.rx.bytes=1000
  net.0.rx.pkts=10
  net.0.tx.bytes=2000
  net.0.tx.pkts=20
`

// A newer libvirt adds groups an old one never had. Everything here is
// additive on top of sampleDomStats.
const sampleDomStatsNew = sampleDomStats + `  cpu.user=100000000000
  cpu.system=23456789000
  vcpu.current=2
  vcpu.maximum=4
  vcpu.0.state=1
  vcpu.0.time=60000000000
  vcpu.0.wait=1000000000
  vcpu.0.delay=250000000
  vcpu.1.state=1
  vcpu.1.time=63456789000
  vcpu.1.wait=2000000000
  vcpu.1.delay=250000000
  balloon.swap_in=0
  balloon.swap_out=4096
  balloon.major_fault=12
  balloon.minor_fault=34567
  balloon.unused=1048576
  balloon.available=4000000
  balloon.usable=3000000
  block.0.rd.times=5000000000
  block.0.wr.times=7000000000
  block.0.fl.reqs=9
  block.0.fl.times=100000000
  block.0.allocation=10737418240
  block.0.capacity=21474836480
  block.0.physical=10737418240
  net.0.rx.errs=1
  net.0.rx.drop=2
  net.0.tx.errs=3
  net.0.tx.drop=4
  dirtyrate.calc_status=2
  dirtyrate.calc_start_time=1000
  dirtyrate.calc_period=1
  dirtyrate.megabytes_per_second=12
`

func TestParseDomainStats(t *testing.T) {
	s := parseDomainStats(sampleDomStats)
	if s.CPUTime != 123456789000 {
		t.Errorf("CPUTime = %d", s.CPUTime)
	}
	// rss (2 GiB) is the usage; maximum (8 GiB) is the ceiling.
	if s.MemoryUsageMB != 2048 || s.MemoryAvailableMB != 6144 || s.MemoryUsagePercent != 25 {
		t.Errorf("memory = used %d avail %d pct %v", s.MemoryUsageMB, s.MemoryAvailableMB, s.MemoryUsagePercent)
	}
	if s.DiskReadBytes != 4096 || s.DiskWriteBytes != 8192 || s.DiskReadOps != 100 || s.DiskWriteOps != 50 {
		t.Errorf("disk = %+v", s)
	}
	if s.NetworkRxBytes != 1000 || s.NetworkTxBytes != 2000 || s.NetworkRxPackets != 10 || s.NetworkTxPackets != 20 {
		t.Errorf("net = %+v", s)
	}
	if s.Uptime != 0 || s.CPUUsageKnown {
		t.Error("domstats carries neither uptime nor utilization; neither may be invented")
	}
	// An old libvirt reports none of the newer groups, and none may be claimed.
	if s.CPUSplitKnown || s.VCPUWaitKnown || s.VCPUDelayKnown || s.GuestMemoryKnown ||
		s.MemoryFaultsKnown || s.DiskTimingKnown || s.DiskAllocationKnown || s.NetworkErrorsKnown || s.DirtyRateKnown {
		t.Errorf("groups an old libvirt does not report were marked known: %+v", s)
	}
}

func TestParseDomainStats_NewerGroups(t *testing.T) {
	s := parseDomainStats(sampleDomStatsNew)

	if !s.CPUSplitKnown || s.CPUUserTime != 100000000000 || s.CPUSystemTime != 23456789000 {
		t.Errorf("cpu split = %+v", s)
	}
	if s.VCPUCurrent != 2 || s.VCPUMaximum != 4 {
		t.Errorf("vcpu counts = %d/%d", s.VCPUCurrent, s.VCPUMaximum)
	}
	if !s.VCPUWaitKnown || s.VCPUWaitTime != 3000000000 || !s.VCPUDelayKnown || s.VCPUDelayTime != 500000000 {
		t.Errorf("vcpu wait/delay = %d/%d", s.VCPUWaitTime, s.VCPUDelayTime)
	}
	// Guest view: total = available (4000000 KiB), used = total - usable.
	if !s.GuestMemoryKnown || s.GuestMemoryTotalMB != 3906 || s.GuestMemoryUsedMB != 976 {
		t.Errorf("guest memory = %+v", s)
	}
	if !s.MemoryFaultsKnown || s.SwapOutKB != 4096 || s.MajorFaults != 12 || s.MinorFaults != 34567 {
		t.Errorf("faults = %+v", s)
	}
	if !s.DiskTimingKnown || s.DiskFlushOps != 9 || s.DiskReadTime != 5000000000 || s.DiskWriteTime != 7000000000 || s.DiskFlushTime != 100000000 {
		t.Errorf("disk timing = %+v", s)
	}
	if !s.DiskAllocationKnown || s.DiskAllocationBytes != 10737418240 || s.DiskCapacityBytes != 21474836480 || s.DiskPhysicalBytes != 10737418240 || s.DiskCount != 1 {
		t.Errorf("disk allocation = %+v", s)
	}
	if !s.NetworkErrorsKnown || s.NetworkRxErrors != 1 || s.NetworkRxDropped != 2 || s.NetworkTxErrors != 3 || s.NetworkTxDropped != 4 {
		t.Errorf("net errors = %+v", s)
	}
	if !s.DirtyRateKnown || s.DirtyRateMBps != 12 {
		t.Errorf("dirty rate = %+v", s)
	}
}

func TestParseDomainStats_GuestMemoryPrefersUnusedOnOldDrivers(t *testing.T) {
	// A balloon driver that predates `usable` reports only `unused`.
	s := parseDomainStats("balloon.available=2000000\nballoon.unused=500000\n")
	if !s.GuestMemoryKnown || s.GuestMemoryUsedMB != (2000000-500000)/1024 {
		t.Errorf("guest memory = %+v", s)
	}
}

func TestParseDomainStats_DirtyRateNeedsCompletedCalc(t *testing.T) {
	s := parseDomainStats("dirtyrate.calc_status=0\ndirtyrate.megabytes_per_second=0\n")
	if s.DirtyRateKnown {
		t.Error("a dirty rate is only a measurement after calc_status=2")
	}
}

const sampleGuestInfo = `hostname            : web-1
os.id               : ubuntu
os.name             : Ubuntu
os.pretty-name      : Ubuntu 24.04.1 LTS
os.version          : 24.04.1 LTS (Noble Numbat)
os.version-id       : 24.04
os.kernel-release   : 6.8.0-45-generic
os.kernel-version   : #45-Ubuntu SMP
os.machine          : x86_64
timezone.name       : UTC
timezone.offset     : 0
user.count          : 1
user.0.name         : root
user.0.login-time   : 1726000000
load.1m             : 0.42
load.5m             : 0.31
load.15m            : 0.25
fs.count            : 2
fs.0.name           : sda1
fs.0.mountpoint     : /
fs.0.fstype         : ext4
fs.0.total-bytes    : 21474836480
fs.0.used-bytes     : 10737418240
fs.0.disk.count     : 1
fs.0.disk.0.alias   : vda
fs.1.name           : sda15
fs.1.mountpoint     : /boot/efi
fs.1.fstype         : vfat
fs.1.total-bytes    : 109422592
fs.1.used-bytes     : 6205440
`

func TestParseGuestInfo(t *testing.T) {
	g := parseGuestInfo(sampleGuestInfo)
	if g == nil {
		t.Fatal("expected a report")
	}
	if g.Hostname != "web-1" || g.OSName != "Ubuntu 24.04.1 LTS" || g.OSVersion != "24.04" || g.OSID != "ubuntu" ||
		g.KernelRelease != "6.8.0-45-generic" || g.Arch != "x86_64" || g.Timezone != "UTC" {
		t.Errorf("identity = %+v", g)
	}
	if !g.UsersKnown || g.Users != 1 {
		t.Errorf("users = %+v", g)
	}
	if !g.LoadKnown || g.Load1 != 0.42 || g.Load5 != 0.31 || g.Load15 != 0.25 {
		t.Errorf("load = %+v", g)
	}
	if len(g.Filesystems) != 2 || g.Filesystems[0].Mountpoint != "/" || g.Filesystems[0].UsedBytes != 10737418240 ||
		g.Filesystems[1].FSType != "vfat" {
		t.Errorf("filesystems = %+v", g.Filesystems)
	}
}

func TestParseGuestInfo_OldAgentWithoutLoadOrUsers(t *testing.T) {
	// libvirt 5.7–9.1 knows hostname/os/fs but not load; the fields it
	// cannot report stay unknown rather than zero.
	g := parseGuestInfo("hostname : db-1\nos.name : Debian\nfs.count : 0\n")
	if g == nil || g.Hostname != "db-1" || g.OSName != "Debian" || g.LoadKnown || g.UsersKnown || len(g.Filesystems) != 0 {
		t.Errorf("report = %+v", g)
	}
}

func TestParseGuestInfo_EmptyIsNil(t *testing.T) {
	if g := parseGuestInfo(""); g != nil {
		t.Errorf("expected nil for an empty report, got %+v", g)
	}
}

func TestParseDomainStats_FallsBackToBalloonCurrent(t *testing.T) {
	s := parseDomainStats("balloon.current=1048576\nballoon.maximum=2097152\n")
	if s.MemoryUsageMB != 1024 || s.MemoryUsagePercent != 50 {
		t.Errorf("memory = used %d pct %v", s.MemoryUsageMB, s.MemoryUsagePercent)
	}
}

func TestLibvirtCPUPercent(t *testing.T) {
	l := NewLibvirtClient(config.VMConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t0 := time.Now()

	if _, ok := l.cpuPercent("web-1", 2, int64(10*time.Second), t0); ok {
		t.Fatal("first observation must not yield a percentage")
	}
	// 5 s of CPU over 10 s wall time on 2 vCPUs = 25%.
	got, ok := l.cpuPercent("web-1", 2, int64(15*time.Second), t0.Add(10*time.Second))
	if !ok || got < 24.99 || got > 25.01 {
		t.Fatalf("cpuPercent = %v, %v; want 25", got, ok)
	}
	// Counter went backwards: the domain restarted.
	if _, ok := l.cpuPercent("web-1", 2, int64(time.Second), t0.Add(20*time.Second)); ok {
		t.Fatal("a reset counter must not yield a percentage")
	}
}

func TestMemoryMB(t *testing.T) {
	cases := []struct {
		value int64
		unit  string
		want  int64
	}{
		{2097152, "KiB", 2048}, {2097152, "", 2048}, {1024, "MiB", 1024}, {2, "GiB", 2048}, {3221225472, "bytes", 3072},
	}
	for _, c := range cases {
		if got := memoryMB(c.value, c.unit); got != c.want {
			t.Errorf("memoryMB(%d,%q) = %d, want %d", c.value, c.unit, got, c.want)
		}
	}
}
