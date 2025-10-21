// Package network provides network metric collection.
package network

import (
	"strings"

	"github.com/shirou/gopsutil/v4/net"
)

// isVirtualInterface checks if an interface is virtual (container/VM created).
func isVirtualInterface(iface net.InterfaceStat) bool {
	name := iface.Name

	// Windows Hyper-V and Docker interfaces
	if strings.HasPrefix(name, "vEthernet") {
		// Skip vEthernet (Default Switch), vEthernet (DockerNAT), vEthernet (nat), etc.
		return true
	}

	// Docker interfaces (Linux)
	if name == "docker0" || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth") {
		return true
	}

	// Podman interfaces (Linux)
	if strings.HasPrefix(name, "cni-podman") {
		return true
	}

	// Libvirt/KVM interfaces (Linux)
	if strings.HasPrefix(name, "virbr") || strings.HasPrefix(name, "vnet") {
		return true
	}

	// Proxmox interfaces (Linux)
	if strings.HasPrefix(name, "vmbr") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "fwbr") || strings.HasPrefix(name, "fwpr") || strings.HasPrefix(name, "fwln") {
		return true
	}

	// Wireguard, tunnels, VPN (all platforms)
	if strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "utun") {
		return true
	}

	// WSL (Windows Subsystem for Linux)
	if strings.Contains(name, "WSL") {
		return true
	}

	return false
}

// shouldMonitorInterface determines if an interface should be monitored.
func shouldMonitorInterface(iface net.InterfaceStat, excludePatterns []string) bool {
	// Skip loopback (check all flags for compatibility)
	for _, flag := range iface.Flags {
		if strings.Contains(strings.ToLower(flag), "loopback") {
			return false
		}
	}

	// Skip if interface is down (must have "up" flag)
	hasUpFlag := false
	for _, flag := range iface.Flags {
		if strings.Contains(strings.ToLower(flag), "up") {
			hasUpFlag = true
			break
		}
	}
	if !hasUpFlag {
		return false
	}

	// Skip virtual interfaces
	if isVirtualInterface(iface) {
		return false
	}

	// Check user-defined exclusion patterns
	for _, pattern := range excludePatterns {
		if matchesPattern(iface.Name, pattern) {
			return false
		}
	}

	return true
}

// matchesPattern performs simple wildcard matching (* only at start/end).
func matchesPattern(name, pattern string) bool {
	if pattern == "" {
		return false
	}

	// Exact match
	if pattern == name {
		return true
	}

	// Prefix match: eth*
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix)
	}

	// Suffix match: *eth
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(name, suffix)
	}

	// Contains match: *eth*
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		middle := strings.TrimPrefix(strings.TrimSuffix(pattern, "*"), "*")
		return strings.Contains(name, middle)
	}

	return false
}
