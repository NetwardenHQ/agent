// Package identity builds the device_identity snapshot: what kind of machine
// this is (gateway, server, cluster), its platform, and its network
// interfaces. Anything that cannot be determined is omitted, never zeroed.
package identity

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/host"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Device roles reported in device_identity.
const (
	RoleGateway = "gateway"
	RoleServer  = "server"
	RoleCluster = "cluster"
)

const maxInterfaces = 64

// Input is everything Build needs; callers fill what they know.
type Input struct {
	Role            string
	Platform        string
	PlatformVersion string
	Vendor          string
	Capabilities    []string
	// InterfaceRoles maps a device name to wan|lan|vpn|other. Only set on
	// gateways; servers leave interface roles out.
	InterfaceRoles map[string]string
	Interfaces     []NetIface
	// Extra holds the allowed keys of a local producer's identity.json
	// (unisense_version).
	Extra map[string]any
}

// NetIface is one interface as read from the OS.
type NetIface struct {
	Name  string
	MAC   string
	Flags net.Flags
	Addrs []net.Addr
}

// Build assembles the snapshot.
func Build(in Input) metrics.Snapshot {
	p := map[string]any{"role": in.Role}
	set := func(k, v string) {
		if v != "" {
			p[k] = v
		}
	}
	set("platform", in.Platform)
	set("platform_version", in.PlatformVersion)
	set("vendor", in.Vendor)
	if len(in.Capabilities) > 0 {
		p["capabilities"] = in.Capabilities
	}
	p["interfaces"] = BuildInterfaces(in.Interfaces, in.InterfaceRoles)
	for k, v := range in.Extra {
		p[k] = v
	}
	return metrics.Snapshot{Type: metrics.SnapshotDeviceIdentity, Payload: p}
}

// BuildInterfaces drops loopback interfaces and interfaces with neither an
// address nor a MAC, lists addresses as CIDR strings without loopback or
// link-local entries, and attaches a role when one is known.
func BuildInterfaces(list []NetIface, roles map[string]string) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, ni := range list {
		if ni.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs := cidrs(ni.Addrs)
		if len(addrs) == 0 && ni.MAC == "" {
			continue
		}
		m := map[string]any{"name": ni.Name, "addresses": addrs}
		if ni.MAC != "" {
			m["mac"] = ni.MAC
		}
		if r := roles[ni.Name]; r != "" {
			m["role"] = r
		}
		out = append(out, m)
		if len(out) == maxInterfaces {
			break
		}
	}
	return out
}

func cidrs(addrs []net.Addr) []string {
	out := []string{}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP == nil {
			continue
		}
		ip := n.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}
		out = append(out, (&net.IPNet{IP: ip, Mask: n.Mask}).String())
	}
	return out
}

// ReadInterfaces lists the host's interfaces. An interface whose addresses
// cannot be read keeps its MAC and gets no addresses.
func ReadInterfaces() []NetIface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]NetIface, 0, len(ifs))
	for i := range ifs {
		addrs, _ := ifs[i].Addrs()
		out = append(out, NetIface{
			Name:  ifs[i].Name,
			MAC:   ifs[i].HardwareAddr.String(),
			Flags: ifs[i].Flags,
			Addrs: addrs,
		})
	}
	return out
}

var (
	platOnce sync.Once
	platID   string
	platVer  string
)

// HostPlatform returns the OS/distro id (ubuntu, debian, freebsd, darwin,
// windows) and its version, "" when unknown. Cached for the process life.
func HostPlatform() (string, string) {
	platOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		info, err := host.InfoWithContext(ctx)
		switch runtime.GOOS {
		case "windows", "darwin":
			platID = runtime.GOOS
		default:
			if err == nil {
				platID = strings.ToLower(info.Platform)
			}
			if platID == "" && runtime.GOOS == "freebsd" {
				platID = "freebsd"
			}
		}
		if err == nil {
			platVer = info.PlatformVersion
		}
	})
	return platID, platVer
}
