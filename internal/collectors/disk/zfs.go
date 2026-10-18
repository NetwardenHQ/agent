package disk

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
)

// ZFS datasets need their own accounting on every OS that has them.
//
// statfs on a dataset reports the dataset's own bytes against the pool's free
// space, so a small root dataset on a large pool reads as ~1% full while the
// pool is nearly full, and every dataset of the pool repeats the same free
// space as a near-identical series. What runs out is the pool's usable
// capacity: USED plus AVAIL of the pool's root dataset in `zfs list`. That is
// net of raidz parity and the pool's slop space; `zpool list` SIZE, ALLOC and
// FREE are raw device bytes and overstate a raidz pool by its parity.
//
// A dataset with a quota or refquota runs out at its own limit, and statfs
// already reports against that limit, so it keeps its own series (a Proxmox
// container's subvol-NNN-disk-N, for instance). Every other dataset is folded
// into one series per pool.

// zfsDataset is one filesystem from `zfs list`.
type zfsDataset struct {
	Used     uint64
	Avail    uint64
	HasQuota bool // quota or refquota set
}

// zfsListFn runs `zfs list`; replaced in tests.
var zfsListFn = func(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "zfs", "list", "-Hp", "-t", "filesystem",
		"-o", "name,used,avail,quota,refquota").Output()
}

// statfsFn is disk.Usage; replaced in tests.
var statfsFn = disk.Usage

// parseZfsList parses `zfs list -Hp -o name,used,avail,quota,refquota`: one
// tab-separated line per dataset with exact byte counts. An unset quota reads
// "0" under -p ("none" or "-" without it).
func parseZfsList(out []byte) (map[string]zfsDataset, error) {
	sets := map[string]zfsDataset{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Tab-separated, and dataset names cannot contain tabs.
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) != 5 {
			return nil, fmt.Errorf("unexpected zfs list line %q", line)
		}
		used, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("zfs list line %q: %w", line, err)
		}
		avail, err := strconv.ParseUint(f[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("zfs list line %q: %w", line, err)
		}
		sets[f[0]] = zfsDataset{Used: used, Avail: avail, HasQuota: quotaSet(f[3]) || quotaSet(f[4])}
	}
	return sets, nil
}

// quotaSet reports whether a quota/refquota column holds a limit.
func quotaSet(v string) bool {
	switch v {
	case "", "0", "-", "none":
		return false
	}
	n, err := strconv.ParseUint(v, 10, 64)
	return err == nil && n > 0
}

// zfsPoolName returns the pool a dataset device belongs to ("zroot/ROOT/default" -> "zroot").
func zfsPoolName(device string) string {
	if i := strings.IndexByte(device, '/'); i >= 0 {
		return device[:i]
	}
	return device
}

// zfsState is the per-Collect ZFS bookkeeping: the `zfs list` answer, read at
// most once, and the pools already reported.
type zfsState struct {
	loaded   bool
	datasets map[string]zfsDataset // nil when `zfs list` failed
	err      error
	seen     map[string]bool
}

// zfsUsage returns the usage to report for a ZFS partition, or skip=true when
// the partition is folded into a pool series already reported this cycle.
func zfsUsage(ctx context.Context, p disk.PartitionStat, st *zfsState) (usage *disk.UsageStat, skip bool, err error) {
	if !st.loaded {
		st.loaded = true
		if st.seen == nil {
			st.seen = map[string]bool{}
		}
		out, lerr := zfsListFn(ctx)
		if lerr == nil {
			st.datasets, lerr = parseZfsList(out)
		}
		if lerr != nil {
			st.err = fmt.Errorf("zfs list: %w", lerr)
		}
	}

	if ds, ok := st.datasets[p.Device]; ok && ds.HasQuota {
		u, err := statfsFn(p.Mountpoint)
		return u, false, err
	}

	pool := zfsPoolName(p.Device)
	if st.seen[pool] {
		return nil, true, nil
	}
	st.seen[pool] = true

	root, ok := st.datasets[pool]
	if !ok || root.Used+root.Avail == 0 {
		// No pool figure (zfs list failed, or the pool root is not listed):
		// the dataset's own statfs is the best available, and the caller
		// says so in the log.
		u, serr := statfsFn(p.Mountpoint)
		if serr != nil {
			return nil, false, serr
		}
		if st.err != nil {
			return u, false, st.err
		}
		return u, false, fmt.Errorf("pool %q not in zfs list", pool)
	}
	total := root.Used + root.Avail
	return &disk.UsageStat{
		Path:        p.Mountpoint,
		Fstype:      p.Fstype,
		Total:       total,
		Used:        root.Used,
		Free:        root.Avail,
		UsedPercent: float64(root.Used) / float64(total) * 100,
	}, false, nil
}
