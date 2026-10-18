//go:build linux
// +build linux

// Package vm provides VM monitoring functionality for the Netwarden agent.
// It supports multiple hypervisors through a common interface.
// VM monitoring is only supported on Linux systems.
package vm

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// VM represents basic virtual machine information.
type VM struct {
	ID         string            `json:"id"`         // UUID, VMID, or other unique identifier
	Name       string            `json:"name"`       // VM name
	Hypervisor string            `json:"hypervisor"` // proxmox, libvirt, kvm, xen, qemu
	Node       string            `json:"node"`       // Proxmox node name (if applicable)
	VMID       int               `json:"vmid"`       // Proxmox VMID (if applicable)
	Status     string            `json:"status"`     // running, stopped, paused, suspended; anything else is unknown
	OSType     string            `json:"os_type"`    // linux, windows, etc.
	CPUCount   int               `json:"cpu_count"`  // Number of vCPUs (0 = not known)
	MemoryMB   int64             `json:"memory_mb"`  // Memory in MB (0 = not known)
	DiskGB     int64             `json:"disk_gb"`    // Disk space in GB
	Labels     map[string]string `json:"labels,omitempty"`
	Created    time.Time         `json:"created"`
}

// VMStats is one VM's resource use at an instant.
//
// Hypervisors differ in what they can say, and libvirt differs by version and
// by whether the guest runs a balloon driver or a guest agent. Every optional
// group therefore carries a Known flag; the collector emits nothing for a
// group that is not known rather than a zero that would read as a
// measurement. The always-present fields are the ones every libvirt since
// 1.2 and every Proxmox report.
type VMStats struct {
	VMID string `json:"vm_id"`

	// ---- CPU ----

	// CPUUsagePercent is utilization of the VM's own vCPUs (100 = every
	// vCPU busy). libvirt derives it from the change in CPU time between two
	// observations, so the first observation of a VM has none.
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	CPUUsageKnown   bool    `json:"-"`
	// CPUTime is cumulative guest CPU time in nanoseconds.
	CPUTime int64 `json:"cpu_time"`
	// CPUUserTime / CPUSystemTime split CPUTime by where the hypervisor spent
	// it on the guest's behalf (libvirt cpu-total group).
	CPUUserTime   int64 `json:"cpu_user_time,omitempty"`
	CPUSystemTime int64 `json:"cpu_system_time,omitempty"`
	CPUSplitKnown bool  `json:"-"`
	// VCPUCurrent / VCPUMaximum are the online and hot-pluggable vCPU counts
	// (0 = not reported).
	VCPUCurrent int `json:"vcpu_current,omitempty"`
	VCPUMaximum int `json:"vcpu_maximum,omitempty"`
	// VCPUWaitTime is cumulative time vCPUs spent runnable but not running
	// (steal, from the guest's point of view). VCPUDelayTime (libvirt 7.3+) is
	// the scheduler delay behind it.
	VCPUWaitTime   int64 `json:"vcpu_wait_time,omitempty"`
	VCPUWaitKnown  bool  `json:"-"`
	VCPUDelayTime  int64 `json:"vcpu_delay_time,omitempty"`
	VCPUDelayKnown bool  `json:"-"`

	// ---- Memory, host view ----

	// MemoryUsageMB is what the guest occupies on the host (RSS where the
	// hypervisor reports it); MemoryAvailableMB the headroom to its ceiling,
	// 0 when the guest is at or over it. MemoryKnown says the usage was
	// reported at all; MemoryLimitKnown that a ceiling was too, which
	// available and percent need.
	MemoryUsageMB      int64   `json:"memory_usage_mb"`
	MemoryAvailableMB  int64   `json:"memory_available_mb"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`
	MemoryKnown        bool    `json:"-"`
	MemoryLimitKnown   bool    `json:"-"`

	// ---- Memory, guest view ----

	// The guest's own accounting, available only when it runs a balloon
	// driver with statistics (libvirt) or a guest agent (Proxmox).
	// GuestMemoryUsedMB is total minus what the guest could reclaim without
	// swapping, the same definition as the host collector's "used".
	GuestMemoryTotalMB      int64   `json:"guest_memory_total_mb,omitempty"`
	GuestMemoryUsedMB       int64   `json:"guest_memory_used_mb,omitempty"`
	GuestMemoryUsagePercent float64 `json:"guest_memory_usage_percent,omitempty"`
	GuestMemoryKnown        bool    `json:"-"`
	// Swap and page-fault counters from the balloon driver, cumulative.
	SwapInKB          int64 `json:"swap_in_kb,omitempty"`
	SwapOutKB         int64 `json:"swap_out_kb,omitempty"`
	MajorFaults       int64 `json:"major_faults,omitempty"`
	MinorFaults       int64 `json:"minor_faults,omitempty"`
	MemoryFaultsKnown bool  `json:"-"`

	// ---- Disk, summed across the VM's block devices ----

	DiskCount      int   `json:"disk_count,omitempty"`
	DiskReadBytes  int64 `json:"disk_read_bytes"`
	DiskWriteBytes int64 `json:"disk_write_bytes"`
	DiskReadOps    int64 `json:"disk_read_ops"`
	DiskWriteOps   int64 `json:"disk_write_ops"`
	// Flushes and cumulative time spent in each operation (nanoseconds).
	DiskFlushOps    int64 `json:"disk_flush_ops,omitempty"`
	DiskReadTime    int64 `json:"disk_read_time,omitempty"`
	DiskWriteTime   int64 `json:"disk_write_time,omitempty"`
	DiskFlushTime   int64 `json:"disk_flush_time,omitempty"`
	DiskTimingKnown bool  `json:"-"`
	// Allocation is what the disk images occupy, Capacity what the guest
	// sees, Physical the on-disk size of the image files.
	DiskAllocationBytes int64 `json:"disk_allocation_bytes,omitempty"`
	DiskCapacityBytes   int64 `json:"disk_capacity_bytes,omitempty"`
	DiskPhysicalBytes   int64 `json:"disk_physical_bytes,omitempty"`
	DiskAllocationKnown bool  `json:"-"`

	// ---- Network, summed across the VM's interfaces ----

	NetworkRxBytes     int64 `json:"network_rx_bytes"`
	NetworkTxBytes     int64 `json:"network_tx_bytes"`
	NetworkRxPackets   int64 `json:"network_rx_packets"`
	NetworkTxPackets   int64 `json:"network_tx_packets"`
	NetworkRxErrors    int64 `json:"network_rx_errors,omitempty"`
	NetworkTxErrors    int64 `json:"network_tx_errors,omitempty"`
	NetworkRxDropped   int64 `json:"network_rx_dropped,omitempty"`
	NetworkTxDropped   int64 `json:"network_tx_dropped,omitempty"`
	NetworkErrorsKnown bool  `json:"-"`

	// DirtyRateMBps is the guest's page dirtying rate, the figure that
	// decides whether a live migration can converge. libvirt 7.2+, and only
	// after an operator has run a measurement (`virsh domdirtyrate-calc`).
	DirtyRateMBps  float64 `json:"dirty_rate_mb_per_second,omitempty"`
	DirtyRateKnown bool    `json:"-"`

	// Uptime in seconds (0 = not reported; libvirt exposes none).
	Uptime int64 `json:"uptime"`

	// Guest is what the guest agent reports about the OS inside, when one
	// is running. nil otherwise.
	Guest *GuestInfo `json:"guest,omitempty"`
}

// GuestFilesystem is one mounted filesystem as the guest agent reports it.
type GuestFilesystem struct {
	Name       string `json:"name"` // device, e.g. sda1
	Mountpoint string `json:"mountpoint"`
	FSType     string `json:"fstype"`
	TotalBytes int64  `json:"total_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
}

// GuestInfo is the guest agent's view from inside the VM (libvirt 5.7+
// `virsh guestinfo`). Every field is optional: agents differ in what they
// implement.
type GuestInfo struct {
	Hostname      string `json:"hostname,omitempty"`
	OSName        string `json:"os_name,omitempty"`
	OSVersion     string `json:"os_version,omitempty"`
	OSID          string `json:"os_id,omitempty"`
	KernelRelease string `json:"kernel_release,omitempty"`
	Arch          string `json:"arch,omitempty"`
	Timezone      string `json:"timezone,omitempty"`

	Users      int  `json:"users,omitempty"`
	UsersKnown bool `json:"-"`

	// Load averages (libvirt 9.2+).
	Load1, Load5, Load15 float64 `json:"-"`
	LoadKnown            bool    `json:"-"`

	Filesystems []GuestFilesystem `json:"filesystems,omitempty"`
}

// HypervisorClient interface for hypervisor implementations.
// This abstraction allows support for Proxmox, libvirt, KVM, Xen, QEMU, etc.
type HypervisorClient interface {
	// Name returns the name of the hypervisor.
	Name() string

	// IsAvailable checks if the hypervisor is available and responding.
	IsAvailable() bool

	// ListVMs returns all VMs managed by this hypervisor.
	ListVMs(ctx context.Context) ([]VM, error)

	// GetVMStats retrieves resource usage statistics for a VM previously
	// returned by ListVMs. The VM carries whatever the hypervisor needs to
	// address it (name, node, VMID), so no second lookup is required.
	GetVMStats(ctx context.Context, vm VM) (*VMStats, error)

	// Close performs cleanup and closes any connections.
	Close() error
}

// NoOpClient implements HypervisorClient for when no hypervisor is available.
type NoOpClient struct{}

// Name returns the client name.
func (n *NoOpClient) Name() string {
	return "none"
}

// IsAvailable always returns false for the no-op client.
func (n *NoOpClient) IsAvailable() bool {
	return false
}

// ListVMs returns an empty list for the no-op client.
func (n *NoOpClient) ListVMs(ctx context.Context) ([]VM, error) {
	return nil, nil
}

// GetVMStats returns nil for the no-op client.
func (n *NoOpClient) GetVMStats(ctx context.Context, vm VM) (*VMStats, error) {
	return nil, nil
}

// Close is a no-op for the no-op client.
func (n *NoOpClient) Close() error {
	return nil
}

// HypervisorDetector detects available hypervisors on the system.
type HypervisorDetector struct{}

// NewHypervisorDetector creates a new hypervisor detector.
func NewHypervisorDetector() *HypervisorDetector {
	return &HypervisorDetector{}
}

// DetectHypervisor attempts to detect available hypervisors in order of preference.
func (d *HypervisorDetector) DetectHypervisor() string {
	// Proxmox first, as the more specific match.
	if d.isProxmoxAvailable() {
		return "proxmox"
	}

	if d.isLibvirtAvailable() {
		return "libvirt"
	}

	return "none"
}

// isProxmoxAvailable checks if we're running on a Proxmox VE node.
func (d *HypervisorDetector) isProxmoxAvailable() bool {
	if _, err := os.Stat("/etc/pve"); err == nil {
		return true
	}

	if _, err := exec.LookPath("pvesh"); err == nil {
		return true
	}

	if _, err := exec.LookPath("qm"); err == nil {
		return true
	}

	return false
}

// isLibvirtAvailable checks if libvirt is available.
func (d *HypervisorDetector) isLibvirtAvailable() bool {
	if _, err := exec.LookPath("virsh"); err == nil {
		return true
	}

	sockets := []string{
		"/var/run/libvirt/libvirt-sock",
		"/run/libvirt/libvirt-sock",
	}

	for _, socket := range sockets {
		if _, err := os.Stat(socket); err == nil {
			return true
		}
	}

	return false
}

// GetHypervisorType determines hypervisor type from libvirt URI or system detection.
func (d *HypervisorDetector) GetHypervisorType(uri string) string {
	if uri == "" {
		return d.DetectHypervisor()
	}

	if strings.HasPrefix(uri, "qemu://") {
		return "kvm"
	} else if strings.HasPrefix(uri, "xen://") {
		return "xen"
	} else if strings.Contains(uri, "qemu") {
		return "qemu"
	} else if strings.Contains(uri, "xen") {
		return "xen"
	}

	return "libvirt"
}
