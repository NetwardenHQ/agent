package disk

import (
	"context"
	"errors"
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
)

// `zfs list -Hp -t filesystem -o name,used,avail,quota,refquota` as an
// OPNsense box (root on ZFS, single pool) prints it.
const opnsenseZfsList = "zroot\t98957123584\t24732545024\t0\t0\n" +
	"zroot/ROOT\t60123456512\t24732545024\t0\t0\n" +
	"zroot/ROOT/default\t60123444224\t24732545024\t0\t0\n" +
	"zroot/tmp\t1060864\t24732545024\t0\t0\n" +
	"zroot/var\t38000000000\t24732545024\t0\t0\n" +
	"zroot/var/log\t2000000000\t24732545024\t0\t0\n"

// A Proxmox node: root on rpool, and an LXC container whose subvol has a
// refquota (the size the container was given).
const proxmoxZfsList = "rpool\t400000000000\t500000000000\t0\t0\n" +
	"rpool/ROOT\t20000000000\t500000000000\t0\t0\n" +
	"rpool/ROOT/pve-1\t20000000000\t500000000000\t0\t0\n" +
	"rpool/data\t300000000000\t500000000000\t0\t0\n" +
	"rpool/data/subvol-101-disk-0\t2147483648\t6442450944\t0\t8589934592\n"

func withZfs(t *testing.T, list string, listErr error) *[]string {
	t.Helper()
	oldList, oldStat := zfsListFn, statfsFn
	t.Cleanup(func() { zfsListFn, statfsFn = oldList, oldStat })
	zfsListFn = func(context.Context) ([]byte, error) { return []byte(list), listErr }
	var statted []string
	statfsFn = func(path string) (*disk.UsageStat, error) {
		statted = append(statted, path)
		return &disk.UsageStat{Path: path, Total: 100, Used: 25, Free: 75}, nil
	}
	return &statted
}

func zfsPart(device, mount string) disk.PartitionStat {
	return disk.PartitionStat{Device: device, Mountpoint: mount, Fstype: "zfs"}
}

func TestParseZfsList(t *testing.T) {
	sets, err := parseZfsList([]byte(proxmoxZfsList))
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 5 {
		t.Fatalf("got %d datasets", len(sets))
	}
	if r := sets["rpool"]; r.Used != 400000000000 || r.Avail != 500000000000 || r.HasQuota {
		t.Fatalf("rpool = %+v", r)
	}
	if !sets["rpool/data/subvol-101-disk-0"].HasQuota {
		t.Fatal("refquota not detected")
	}
	if s, _ := parseZfsList([]byte("tank/a\t1\t2\t-\tnone\n")); s["tank/a"].HasQuota {
		t.Fatal("'-'/'none' read as a quota")
	}
	if _, err := parseZfsList([]byte("zroot\t1\t2\n")); err == nil {
		t.Fatal("short line must be an error")
	}
	if _, err := parseZfsList([]byte("zroot\tx\t2\t0\t0\n")); err == nil {
		t.Fatal("non-numeric used must be an error")
	}
}

// OPNsense: the root dataset stands for the pool, at the pool's usable
// capacity (root USED + AVAIL), and every other dataset of the pool is folded
// into it rather than repeating the same free space.
func TestZfsUsage_OPNsenseReportsPoolOnce(t *testing.T) {
	statted := withZfs(t, opnsenseZfsList, nil)
	var st zfsState
	u, skip, err := zfsUsage(context.Background(), zfsPart("zroot/ROOT/default", "/"), &st)
	if err != nil || skip {
		t.Fatalf("root: skip=%v err=%v", skip, err)
	}
	if u.Total != 98957123584+24732545024 || u.Used != 98957123584 || u.Free != 24732545024 {
		t.Fatalf("usage = %+v, want the pool's root dataset", u)
	}
	if u.UsedPercent < 79.9 || u.UsedPercent > 80.1 {
		t.Fatalf("UsedPercent = %f, want ~80 (pool), not the root dataset's share", u.UsedPercent)
	}
	for _, p := range []disk.PartitionStat{zfsPart("zroot/tmp", "/tmp"), zfsPart("zroot/var/log", "/var/log")} {
		if _, skip, _ := zfsUsage(context.Background(), p, &st); !skip {
			t.Errorf("%s not folded into its pool", p.Device)
		}
	}
	if len(*statted) != 0 {
		t.Errorf("statfs called for %v; pool datasets need none", *statted)
	}
}

// Linux root-on-ZFS gets the same single pool series, and a dataset with its
// own quota keeps its own statfs figure.
func TestZfsUsage_ProxmoxQuotaDatasetKeepsItsOwnSeries(t *testing.T) {
	statted := withZfs(t, proxmoxZfsList, nil)
	var st zfsState
	u, skip, err := zfsUsage(context.Background(), zfsPart("rpool/ROOT/pve-1", "/"), &st)
	if err != nil || skip || u.Total != 900000000000 {
		t.Fatalf("root: %+v skip=%v err=%v", u, skip, err)
	}
	if _, skip, _ := zfsUsage(context.Background(), zfsPart("rpool/data", "/rpool/data"), &st); !skip {
		t.Error("rpool/data not folded into its pool")
	}
	u, skip, err = zfsUsage(context.Background(), zfsPart("rpool/data/subvol-101-disk-0", "/rpool/data/subvol-101-disk-0"), &st)
	if err != nil || skip {
		t.Fatalf("subvol: skip=%v err=%v", skip, err)
	}
	if u.Total != 100 || len(*statted) != 1 || (*statted)[0] != "/rpool/data/subvol-101-disk-0" {
		t.Fatalf("quota dataset must report its own statfs: %+v statted=%v", u, *statted)
	}
}

// When `zfs list` fails the first dataset's statfs is reported (with the
// error, for the log) and the rest of the pool is still folded.
func TestZfsUsage_ListFailureFallsBackOncePerPool(t *testing.T) {
	statted := withZfs(t, "", errors.New("no zfs"))
	var st zfsState
	u, skip, err := zfsUsage(context.Background(), zfsPart("zroot/ROOT/default", "/"), &st)
	if u == nil || skip || err == nil {
		t.Fatalf("fallback: %+v skip=%v err=%v", u, skip, err)
	}
	if _, skip, _ := zfsUsage(context.Background(), zfsPart("zroot/tmp", "/tmp"), &st); !skip {
		t.Error("second dataset not folded")
	}
	if len(*statted) != 1 {
		t.Errorf("statted = %v", *statted)
	}
}

func TestZFSPoolName(t *testing.T) {
	for in, want := range map[string]string{"zroot/ROOT/default": "zroot", "zroot": "zroot", "tank/home": "tank"} {
		if got := zfsPoolName(in); got != want {
			t.Errorf("zfsPoolName(%q) = %q, want %q", in, got, want)
		}
	}
}
