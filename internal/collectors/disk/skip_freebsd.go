//go:build freebsd

package disk

import (
	"github.com/shirou/gopsutil/v4/disk"
)

// pseudoFS are mounts that carry no storage of their own on FreeBSD.
var pseudoFS = map[string]bool{
	"devfs": true, "fdescfs": true, "procfs": true, "linprocfs": true,
	"linsysfs": true, "tmpfs": true, "nullfs": true, "autofs": true,
	"unionfs": true,
}

// skipPlatformPartition drops pseudo filesystems. ZFS datasets are folded
// into one series per pool on every OS, in zfs.go.
func skipPlatformPartition(p disk.PartitionStat) bool {
	return pseudoFS[p.Fstype]
}
