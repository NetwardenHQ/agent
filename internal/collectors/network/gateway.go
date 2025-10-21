// Package network provides network metric collection.
package network

import (
	"net"

	"github.com/jackpal/gateway"
	gopsnet "github.com/shirou/gopsutil/v4/net"
)

// getDefaultInterface returns the interface name that owns the default route.
func getDefaultInterface() (string, error) {
	// Get default gateway IP
	gwIP, err := gateway.DiscoverGateway()
	if err != nil {
		return "", err
	}

	// Get all network interfaces
	interfaces, err := gopsnet.Interfaces()
	if err != nil {
		return "", err
	}

	// Find which interface can reach the gateway
	for _, iface := range interfaces {
		for _, addr := range iface.Addrs {
			// Parse the CIDR address
			ip, ipnet, err := net.ParseCIDR(addr.Addr)
			if err != nil {
				continue
			}

			// Check if gateway is in this subnet
			if ipnet.Contains(gwIP) {
				return iface.Name, nil
			}

			// Also check if this is the interface IP
			if ip.Equal(gwIP) {
				return iface.Name, nil
			}
		}
	}

	// Fallback: return first non-loopback interface that's UP
	for _, iface := range interfaces {
		if shouldMonitorInterface(iface, nil) {
			return iface.Name, nil
		}
	}

	return "", nil
}
