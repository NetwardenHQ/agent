//go:build linux
// +build linux

package vm

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"netwarden/internal/config"
)

// LibvirtClient implements HypervisorClient for libvirt-based hypervisors.
type LibvirtClient struct {
	config   config.VMConfig
	logger   *slog.Logger
	uri      string
	detector *HypervisorDetector
}

// LibvirtDomain represents a libvirt domain from XML.
type LibvirtDomain struct {
	XMLName xml.Name `xml:"domain"`
	Type    string   `xml:"type,attr"`
	Name    string   `xml:"name"`
	UUID    string   `xml:"uuid"`
	Memory  struct {
		Unit  string `xml:"unit,attr"`
		Value int64  `xml:",chardata"`
	} `xml:"memory"`
	VCPU struct {
		Placement string `xml:"placement,attr"`
		Value     int    `xml:",chardata"`
	} `xml:"vcpu"`
	OS struct {
		Type struct {
			Arch    string `xml:"arch,attr"`
			Machine string `xml:"machine,attr"`
			Value   string `xml:",chardata"`
		} `xml:"type"`
	} `xml:"os"`
}

// NewLibvirtClient creates a new libvirt hypervisor client.
func NewLibvirtClient(config config.VMConfig, logger *slog.Logger) *LibvirtClient {
	uri := config.LibvirtURI
	if uri == "" {
		// Auto-detect appropriate URI
		uri = "qemu:///system" // Default for KVM
	}

	return &LibvirtClient{
		config:   config,
		logger:   logger,
		uri:      uri,
		detector: NewHypervisorDetector(),
	}
}

// Name returns the hypervisor name based on the URI.
func (l *LibvirtClient) Name() string {
	return l.detector.GetHypervisorType(l.uri)
}

// IsAvailable checks if virsh command is available and can connect.
func (l *LibvirtClient) IsAvailable() bool {
	// Check if virsh is available
	if _, err := exec.LookPath("virsh"); err != nil {
		l.logger.Debug("virsh command not found")
		return false
	}

	// Test connection with a quick command
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "virsh", "-c", l.uri, "version")
	if err := cmd.Run(); err != nil {
		l.logger.Debug("virsh connection test failed", "uri", l.uri, "error", err)
		return false
	}

	return true
}

// execVirsh executes a virsh command and returns the output.
func (l *LibvirtClient) execVirsh(ctx context.Context, args ...string) ([]byte, error) {
	// Prepend connection URI to arguments
	allArgs := append([]string{"-c", l.uri}, args...)
	cmd := exec.CommandContext(ctx, "virsh", allArgs...)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("virsh command failed: %s (stderr: %s)", err, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("virsh command failed: %w", err)
	}

	return output, nil
}

// ListVMs returns all VMs from libvirt.
func (l *LibvirtClient) ListVMs(ctx context.Context) ([]VM, error) {
	// Get list of all domains (both running and shut off)
	output, err := l.execVirsh(ctx, "list", "--all", "--name")
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	vms := make([]VM, 0, len(lines))

	for _, line := range lines {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}

		vm, err := l.getVMDetails(ctx, name)
		if err != nil {
			l.logger.Warn("failed to get VM details", "vm", name, "error", err)
			continue
		}

		vms = append(vms, *vm)
	}

	l.logger.Debug("libvirt: listed VMs", "count", len(vms), "uri", l.uri)
	return vms, nil
}

// getVMDetails retrieves detailed information about a specific VM.
func (l *LibvirtClient) getVMDetails(ctx context.Context, name string) (*VM, error) {
	// Get domain info
	infoOutput, err := l.execVirsh(ctx, "dominfo", name)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain info: %w", err)
	}

	// Get domain XML for more details
	xmlOutput, err := l.execVirsh(ctx, "dumpxml", name)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain XML: %w", err)
	}

	// Parse domain info
	info := l.parseDomainInfo(string(infoOutput))

	// Parse domain XML
	var domainXML LibvirtDomain
	if err := xml.Unmarshal(xmlOutput, &domainXML); err != nil {
		l.logger.Warn("failed to parse domain XML", "vm", name, "error", err)
		// Continue with basic info if XML parsing fails
	}

	vm := &VM{
		ID:         info["UUID"],
		Name:       name,
		Hypervisor: l.Name(),
		Node:       "", // Not applicable for libvirt
		VMID:       0,  // Not applicable for libvirt
		Status:     l.normalizeStatus(info["State"]),
		OSType:     domainXML.OS.Type.Value,
		CPUCount:   domainXML.VCPU.Value,
		MemoryMB:   l.parseMemoryFromXML(domainXML.Memory),
		DiskGB:     0, // Would need additional XML parsing for accurate disk size
		Labels:     make(map[string]string),
		Created:    time.Time{}, // Not easily available from virsh
	}

	// Add type-specific labels
	vm.Labels["hypervisor_type"] = domainXML.Type
	vm.Labels["arch"] = domainXML.OS.Type.Arch
	if domainXML.UUID != "" {
		vm.Labels["uuid"] = domainXML.UUID
	}

	return vm, nil
}

// parseDomainInfo parses the output of 'virsh dominfo' command.
func (l *LibvirtClient) parseDomainInfo(output string) map[string]string {
	info := make(map[string]string)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			info[key] = value
		}
	}

	return info
}

// parseMemoryFromXML converts libvirt memory specification to MB.
func (l *LibvirtClient) parseMemoryFromXML(memory struct {
	Unit  string `xml:"unit,attr"`
	Value int64  `xml:",chardata"`
}) int64 {
	value := memory.Value
	unit := strings.ToLower(memory.Unit)

	switch unit {
	case "bytes", "b":
		return value / (1024 * 1024) // Convert bytes to MB
	case "kb", "kib":
		return value / 1024 // Convert KB to MB
	case "mb", "mib":
		return value // Already in MB
	case "gb", "gib":
		return value * 1024 // Convert GB to MB
	default:
		// Default assumption: KiB (libvirt's default)
		return value / 1024
	}
}

// normalizeStatus converts libvirt status to standardized format.
func (l *LibvirtClient) normalizeStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))

	switch {
	case strings.Contains(status, "running"):
		return "running"
	case strings.Contains(status, "shut off"), strings.Contains(status, "shutoff"):
		return "stopped"
	case strings.Contains(status, "paused"):
		return "paused"
	case strings.Contains(status, "suspended"):
		return "paused"
	default:
		return status
	}
}

// GetVMStats retrieves detailed statistics for a specific VM.
func (l *LibvirtClient) GetVMStats(ctx context.Context, vmID string) (*VMStats, error) {
	// Find VM name by UUID
	vmName, err := l.findVMNameByUUID(ctx, vmID)
	if err != nil {
		return nil, fmt.Errorf("failed to find VM by UUID %s: %w", vmID, err)
	}

	// Get domain stats
	output, err := l.execVirsh(ctx, "domstats", vmName)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain stats: %w", err)
	}

	stats := l.parseDomainStats(string(output))

	// Get additional info from dominfo
	infoOutput, err := l.execVirsh(ctx, "dominfo", vmName)
	if err != nil {
		l.logger.Warn("failed to get additional domain info", "vm", vmName, "error", err)
	} else {
		info := l.parseDomainInfo(string(infoOutput))
		// Add uptime if available (though it's not typically in dominfo)
		if uptimeStr, exists := info["Uptime"]; exists {
			if uptime, err := strconv.ParseInt(uptimeStr, 10, 64); err == nil {
				stats.Uptime = uptime
			}
		}
	}

	return stats, nil
}

// findVMNameByUUID finds the VM name corresponding to a UUID.
func (l *LibvirtClient) findVMNameByUUID(ctx context.Context, uuid string) (string, error) {
	// Try to get domain name directly by UUID
	output, err := l.execVirsh(ctx, "domname", uuid)
	if err == nil && len(output) > 0 {
		return strings.TrimSpace(string(output)), nil
	}

	// Fallback: list all domains and match UUID
	vms, err := l.ListVMs(ctx)
	if err != nil {
		return "", err
	}

	for _, vm := range vms {
		if vm.ID == uuid {
			return vm.Name, nil
		}
	}

	return "", fmt.Errorf("VM with UUID %s not found", uuid)
}

// parseDomainStats parses the output of 'virsh domstats' command.
func (l *LibvirtClient) parseDomainStats(output string) *VMStats {
	stats := &VMStats{
		VMID: "",
	}

	// Parse key-value pairs from domstats output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "=") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		valueStr := strings.TrimSpace(parts[1])

		// Parse numeric values
		if value, err := strconv.ParseFloat(valueStr, 64); err == nil {
			switch {
			case strings.Contains(key, "cpu.time"):
				stats.CPUTime = int64(value * 1e9) // Convert seconds to nanoseconds
			case strings.Contains(key, "cpu.util"):
				stats.CPUUsagePercent = value
			case strings.Contains(key, "balloon.current"):
				stats.MemoryUsageMB = int64(value) / 1024 // Convert KB to MB
			case strings.Contains(key, "balloon.maximum"):
				stats.MemoryAvailableMB = int64(value) / 1024 // Convert KB to MB
			case strings.Contains(key, "block") && strings.Contains(key, "rd.bytes"):
				stats.DiskReadBytes += int64(value)
			case strings.Contains(key, "block") && strings.Contains(key, "wr.bytes"):
				stats.DiskWriteBytes += int64(value)
			case strings.Contains(key, "block") && strings.Contains(key, "rd.reqs"):
				stats.DiskReadOps += int64(value)
			case strings.Contains(key, "block") && strings.Contains(key, "wr.reqs"):
				stats.DiskWriteOps += int64(value)
			case strings.Contains(key, "net") && strings.Contains(key, "rx.bytes"):
				stats.NetworkRxBytes += int64(value)
			case strings.Contains(key, "net") && strings.Contains(key, "tx.bytes"):
				stats.NetworkTxBytes += int64(value)
			case strings.Contains(key, "net") && strings.Contains(key, "rx.pkts"):
				stats.NetworkRxPackets += int64(value)
			case strings.Contains(key, "net") && strings.Contains(key, "tx.pkts"):
				stats.NetworkTxPackets += int64(value)
			}
		}
	}

	// Calculate memory usage percentage
	if stats.MemoryUsageMB > 0 && stats.MemoryAvailableMB > 0 {
		totalMem := stats.MemoryUsageMB + stats.MemoryAvailableMB
		stats.MemoryUsagePercent = float64(stats.MemoryUsageMB) / float64(totalMem) * 100.0
	}

	// Calculate uptime from CPU time if not already set (rough approximation)
	if stats.Uptime == 0 && stats.CPUTime > 0 {
		// This is a very rough estimate and may not be accurate
		stats.Uptime = stats.CPUTime / 1e9 // Convert nanoseconds to seconds
	}

	return stats
}

// Close closes any connections to libvirt.
func (l *LibvirtClient) Close() error {
	// virsh commands don't maintain persistent connections
	return nil
}
