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
	Status     string            `json:"status"`     // running, stopped, paused, suspended
	OSType     string            `json:"os_type"`    // linux, windows, etc.
	CPUCount   int               `json:"cpu_count"`  // Number of vCPUs
	MemoryMB   int64             `json:"memory_mb"`  // Memory in MB
	DiskGB     int64             `json:"disk_gb"`    // Disk space in GB
	Labels     map[string]string `json:"labels,omitempty"`
	Created    time.Time         `json:"created"`
}

// VMStats represents VM resource usage metrics.
type VMStats struct {
	VMID               string  `json:"vm_id"`
	CPUUsagePercent    float64 `json:"cpu_usage_percent"`
	CPUTime            int64   `json:"cpu_time"`             // CPU time in nanoseconds
	MemoryUsageMB      int64   `json:"memory_usage_mb"`      // Memory usage in MB
	MemoryAvailableMB  int64   `json:"memory_available_mb"`  // Available memory in MB
	MemoryUsagePercent float64 `json:"memory_usage_percent"` // Memory usage percentage
	DiskReadBytes      int64   `json:"disk_read_bytes"`      // Disk read bytes
	DiskWriteBytes     int64   `json:"disk_write_bytes"`     // Disk write bytes
	DiskReadOps        int64   `json:"disk_read_ops"`        // Disk read operations
	DiskWriteOps       int64   `json:"disk_write_ops"`       // Disk write operations
	NetworkRxBytes     int64   `json:"network_rx_bytes"`     // Network received bytes
	NetworkTxBytes     int64   `json:"network_tx_bytes"`     // Network transmitted bytes
	NetworkRxPackets   int64   `json:"network_rx_packets"`   // Network received packets
	NetworkTxPackets   int64   `json:"network_tx_packets"`   // Network transmitted packets
	Uptime             int64   `json:"uptime"`               // VM uptime in seconds
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

	// GetVMStats retrieves resource usage statistics for a VM.
	GetVMStats(ctx context.Context, vmID string) (*VMStats, error)

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
func (n *NoOpClient) GetVMStats(ctx context.Context, vmID string) (*VMStats, error) {
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
	// Check for Proxmox first (most specific)
	if d.isProxmoxAvailable() {
		return "proxmox"
	}

	// Check for libvirt/KVM
	if d.isLibvirtAvailable() {
		return "libvirt"
	}

	return "none"
}

// isProxmoxAvailable checks if we're running on a Proxmox VE node.
func (d *HypervisorDetector) isProxmoxAvailable() bool {
	// Check for Proxmox VE specific files
	if _, err := os.Stat("/etc/pve"); err == nil {
		return true
	}

	// Check for pvesh command
	if _, err := exec.LookPath("pvesh"); err == nil {
		return true
	}

	// Check for qm command (QEMU/KVM management on Proxmox)
	if _, err := exec.LookPath("qm"); err == nil {
		return true
	}

	return false
}

// isLibvirtAvailable checks if libvirt is available.
func (d *HypervisorDetector) isLibvirtAvailable() bool {
	// Check for virsh command
	if _, err := exec.LookPath("virsh"); err == nil {
		return true
	}

	// Check for libvirt socket
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

	// Parse libvirt URI to determine actual hypervisor
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
