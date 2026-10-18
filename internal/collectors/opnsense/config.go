package opnsense

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// configInfo is the small part of /conf/config.xml the collector needs. The
// file also holds password hashes, private keys, API secrets and VPN keys, so
// it is streamed and character data is buffered only inside the elements
// listed in wantedConfigPath; nothing else is kept, stored or logged.
type configInfo struct {
	RevisionTime time.Time
	RevisionUser string
	RevisionDesc string
	HasRevision  bool
	IDSEnabled   bool
	IPSMode      bool

	// Interfaces maps an OPNsense logical interface name (wan, lan, opt1) to
	// its system device (em0). Device names only; no addresses or secrets.
	Interfaces map[string]string
	// Service flags, true only when the config enables the service.
	VPN  bool
	DHCP bool
	DNS  bool
}

// configFlags are the single-valued elements read from config.xml.
var configFlags = map[string]bool{
	"opnsense/revision/time":                               true,
	"opnsense/revision/username":                           true,
	"opnsense/revision/description":                        true,
	"opnsense/OPNsense/IDS/general/enabled":                true,
	"opnsense/OPNsense/IDS/general/ips":                    true,
	"opnsense/OPNsense/wireguard/general/enabled":          true,
	"opnsense/OPNsense/IPsec/general/enabled":              true,
	"opnsense/OPNsense/Kea/dhcp4/general/enabled":          true,
	"opnsense/OPNsense/Kea/dhcp6/general/enabled":          true,
	"opnsense/OPNsense/unboundplus/general/enabled":        true,
	"opnsense/unbound/enable":                              true,
	"opnsense/OPNsense/dnsmasq/enable":                     true,
	"opnsense/dnsmasq/enable":                              true,
	"opnsense/OPNsense/OpenVPN/Instances/Instance/enabled": true,
}

// wantedConfigPath reports whether the text of the element at stack is read.
// Per-instance elements are matched by position, never by value.
func wantedConfigPath(stack []string) bool {
	if configFlags[strings.Join(stack, "/")] {
		return true
	}
	if len(stack) != 4 || stack[0] != "opnsense" {
		return false
	}
	switch {
	case stack[1] == "interfaces" && stack[3] == "if",
		stack[1] == "dhcpd" && stack[3] == "enable",
		stack[1] == "openvpn" && stack[3] == "disable":
		return true
	}
	return false
}

func parseConfig(r io.Reader) (configInfo, error) {
	dec := xml.NewDecoder(r)
	var (
		info  configInfo
		stack []string
		text  strings.Builder
		want  bool

		ovpnInstances, ovpnDisabled int
	)
	info.Interfaces = map[string]string{}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return configInfo{}, fmt.Errorf("config.xml is not valid XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			text.Reset()
			want = wantedConfigPath(stack)
			// Legacy OpenVPN instances; the MVC ones (OPNsense 24+) carry
			// an <enabled> flag instead and are read from configFlags.
			if len(stack) == 3 && stack[0] == "opnsense" && stack[1] == "openvpn" &&
				(stack[2] == "openvpn-server" || stack[2] == "openvpn-client") {
				ovpnInstances++
			}
		case xml.CharData:
			if want {
				text.Write(t)
			}
		case xml.EndElement:
			if want {
				applyConfigValue(&info, stack, strings.TrimSpace(text.String()), &ovpnDisabled)
			}
			text.Reset()
			want = false
			stack = stack[:len(stack)-1]
		}
	}
	if ovpnInstances > ovpnDisabled {
		info.VPN = true
	}
	return info, nil
}

func applyConfigValue(info *configInfo, stack []string, val string, ovpnDisabled *int) {
	switch strings.Join(stack, "/") {
	case "opnsense/revision/time":
		if sec, err := strconv.ParseFloat(val, 64); err == nil && sec > 0 {
			info.RevisionTime = time.Unix(int64(sec), 0)
			info.HasRevision = true
		}
	case "opnsense/revision/username":
		info.RevisionUser = val
	case "opnsense/revision/description":
		info.RevisionDesc = val
	case "opnsense/OPNsense/IDS/general/enabled":
		info.IDSEnabled = val == "1"
	case "opnsense/OPNsense/IDS/general/ips":
		info.IPSMode = val == "1"
	case "opnsense/OPNsense/wireguard/general/enabled",
		"opnsense/OPNsense/IPsec/general/enabled",
		"opnsense/OPNsense/OpenVPN/Instances/Instance/enabled":
		if val == "1" {
			info.VPN = true
		}
	case "opnsense/OPNsense/Kea/dhcp4/general/enabled",
		"opnsense/OPNsense/Kea/dhcp6/general/enabled":
		if val == "1" {
			info.DHCP = true
		}
	case "opnsense/OPNsense/unboundplus/general/enabled",
		"opnsense/unbound/enable",
		"opnsense/OPNsense/dnsmasq/enable",
		"opnsense/dnsmasq/enable":
		if val == "1" {
			info.DNS = true
		}
	default:
		switch {
		case stack[1] == "interfaces":
			if val != "" {
				info.Interfaces[stack[2]] = val
			}
		case stack[1] == "dhcpd":
			if val != "" && val != "0" {
				info.DHCP = true
			}
		case stack[1] == "openvpn":
			if val != "" && val != "0" {
				*ovpnDisabled++
			}
		}
	}
}

const maxDescLabel = 160

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// collectConfig reports configuration changes: who last changed the firewall
// and when, and how many history entries it keeps. Every change in the GUI
// writes a revision, so this is the audit trail of the firewall's rules.
func (c *Collector) collectConfig(_ context.Context, e *emitter) error {
	f, err := os.Open(c.configXML)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := parseConfig(f)
	if err != nil {
		return err
	}
	c.cfg = &info

	if info.HasRevision {
		// Who and why ride on the timestamp, which changes only when the
		// config does; the age gauge stays a single unlabeled series.
		e.gauge("opnsense_config_last_change_age_seconds", e.ts.Sub(info.RevisionTime).Seconds(), nil)
		e.gauge("opnsense_config_last_change_timestamp", float64(info.RevisionTime.Unix()), map[string]string{
			"user":        truncate(info.RevisionUser, 64),
			"description": truncate(info.RevisionDesc, maxDescLabel),
		})
	}
	if matches, gerr := filepath.Glob(filepath.Join(c.backupDir, "config-*.xml")); gerr == nil {
		e.gauge("opnsense_config_backups", float64(len(matches)), nil)
	}
	return nil
}
