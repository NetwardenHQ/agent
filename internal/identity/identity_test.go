package identity

import (
	"net"
	"testing"
)

func ipnet(s string) *net.IPNet {
	ip, n, _ := net.ParseCIDR(s)
	n.IP = ip
	return n
}

func TestBuildInterfaces(t *testing.T) {
	list := []NetIface{
		{Name: "lo0", Flags: net.FlagLoopback, Addrs: []net.Addr{ipnet("127.0.0.1/8")}},
		{Name: "em0", MAC: "aa:bb:cc:dd:ee:01", Addrs: []net.Addr{ipnet("203.0.113.10/24"), ipnet("fe80::1/64"), ipnet("2001:db8::5/64"), ipnet("::1/128")}},
		{Name: "em1", MAC: "aa:bb:cc:dd:ee:02", Addrs: []net.Addr{ipnet("10.0.0.1/24")}},
		{Name: "pflog0"},
		{Name: "em2", MAC: "aa:bb:cc:dd:ee:03"},
	}
	got := BuildInterfaces(list, map[string]string{"em0": "wan", "em1": "lan"})
	if len(got) != 3 {
		t.Fatalf("want em0, em1, em2 only: %v", got)
	}
	em0 := got[0]
	addrs := em0["addresses"].([]string)
	if len(addrs) != 2 || addrs[0] != "203.0.113.10/24" || addrs[1] != "2001:db8::5/64" || em0["role"] != "wan" {
		t.Fatalf("em0: %v", em0)
	}
	if got[1]["role"] != "lan" {
		t.Fatal("lan role")
	}
	if _, has := got[2]["role"]; has {
		t.Fatal("unmapped interface must have no role")
	}
}

func TestServerOmitsRolesAndUnknowns(t *testing.T) {
	s := Build(Input{Role: RoleServer, Platform: "ubuntu", Interfaces: []NetIface{{Name: "eth0", MAC: "aa:bb:cc:dd:ee:01", Addrs: []net.Addr{ipnet("10.0.0.5/24")}}}})
	p := s.Payload
	if s.Type != "device_identity" || p["role"] != "server" || p["platform"] != "ubuntu" {
		t.Fatalf("%v", p)
	}
	for _, k := range []string{"platform_version", "vendor", "capabilities", "unisense_version"} {
		if _, has := p[k]; has {
			t.Fatalf("%s must be omitted when unknown", k)
		}
	}
	if _, has := p["interfaces"].([]map[string]any)[0]["role"]; has {
		t.Fatal("servers omit interface role")
	}
}

func TestExtraMerged(t *testing.T) {
	s := Build(Input{Role: RoleGateway, Extra: map[string]any{"unisense_version": "1.0"}})
	if s.Payload["unisense_version"] != "1.0" {
		t.Fatal("extra missing")
	}
}
