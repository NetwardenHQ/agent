//go:build !freebsd

package disk

import "github.com/shirou/gopsutil/v4/disk"

// skipPlatformPartition has no platform-specific rules outside FreeBSD; the
// Windows and Linux filters live inline in Collect.
func skipPlatformPartition(disk.PartitionStat) bool { return false }
