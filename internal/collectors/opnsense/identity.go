package opnsense

import (
	"encoding/json"
	"os"
	"strings"
)

// Identity is what the OPNsense collector can verify about the box for the
// device_identity snapshot. Everything unknown is left empty, never guessed.
type Identity struct {
	// Version is the OPNsense release (product_version), "" when unreadable.
	Version string
	// Capabilities lists what is provably enabled or present: firewall and
	// nat always, the rest only when config.xml or the filesystem says so.
	Capabilities []string
	// InterfaceRoles maps a system device name (em0) to wan|lan|vpn|other,
	// derived from config.xml. Nil when config.xml cannot be read.
	InterfaceRoles map[string]string
}

// Where the os-crowdsec plugin leaves its tooling and configuration.
const (
	defaultCrowdSecBin = "/usr/local/bin/cscli"
	defaultCrowdSecCfg = "/usr/local/etc/crowdsec/config.yaml"
)

// Identity reads config.xml and the version marker. config.xml is streamed
// and only interface names and service flags are kept.
func (c *Collector) Identity() (Identity, error) {
	id := Identity{Capabilities: []string{"firewall", "nat"}}

	if raw, err := os.ReadFile(c.versionMarker); err == nil {
		var v struct {
			ProductVersion string `json:"product_version"`
		}
		if json.Unmarshal(raw, &v) == nil {
			id.Version = strings.TrimSpace(v.ProductVersion)
		}
	}

	f, err := os.Open(c.configXML)
	if err != nil {
		return id, err
	}
	defer f.Close()
	info, err := parseConfig(f)
	if err != nil {
		return id, err
	}

	if info.IDSEnabled {
		id.Capabilities = append(id.Capabilities, "ids")
	}
	if info.VPN {
		id.Capabilities = append(id.Capabilities, "vpn")
	}
	if info.DHCP {
		id.Capabilities = append(id.Capabilities, "dhcp")
	}
	if info.DNS {
		id.Capabilities = append(id.Capabilities, "dns")
	}
	if fileExists(c.crowdsecBin) && fileExists(c.crowdsecCfg) {
		id.Capabilities = append(id.Capabilities, "crowdsec")
	}

	id.InterfaceRoles = make(map[string]string, len(info.Interfaces))
	for logical, dev := range info.Interfaces {
		id.InterfaceRoles[dev] = interfaceRole(logical, dev)
	}
	return id, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// interfaceRole classifies one configured interface. wan stays wan; a tunnel
// device (wg, ovpn, tun, ipsec, enc, gif, gre) is vpn whatever its logical name;
// lan and optN are lan; any other configured interface is other.
func interfaceRole(logical, dev string) string {
	if logical == "wan" {
		return "wan"
	}
	for _, p := range []string{"wg", "ovpn", "tun", "ipsec", "enc", "gif", "gre"} {
		if strings.HasPrefix(dev, p) {
			return "vpn"
		}
	}
	if logical == "lan" || isOptN(logical) {
		return "lan"
	}
	return "other"
}

func isOptN(s string) bool {
	if !strings.HasPrefix(s, "opt") || len(s) == 3 {
		return false
	}
	for _, r := range s[3:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
