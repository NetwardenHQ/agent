package security

import "testing"

// classifySockets is shared by the Linux (ss/netstat) and gopsutil
// (macOS/Windows) collectors precisely so exposure is scored identically on
// every platform. These cases pin that behaviour.
func TestClassifySockets(t *testing.T) {
	sockets := []listeningSocket{
		{Proto: "tcp", Port: 22, BindAddr: "0.0.0.0"},     // public ssh  -> management
		{Proto: "tcp", Port: 5432, BindAddr: "127.0.0.1"}, // loopback pg -> NOT exposed
		{Proto: "tcp", Port: 3306, BindAddr: "10.0.0.5"},  // LAN mysql   -> management
		{Proto: "tcp", Port: 8080, BindAddr: "0.0.0.0"},   // public, not management
		{Proto: "udp", Port: 53, BindAddr: "127.0.0.53"},  // loopback dns
	}

	total, public, loopback, management, parts := classifySockets(sockets)

	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if public != 2 {
		t.Errorf("public = %d, want 2 (22, 8080)", public)
	}
	if loopback != 2 {
		t.Errorf("loopback = %d, want 2 (5432, 53)", loopback)
	}
	// 22 (wildcard) and 3306 (routable LAN IP) are reachable; 5432 is not.
	if management != 2 {
		t.Errorf("management = %d, want 2 (ssh, mysql); got parts %v", management, parts)
	}
	for _, p := range parts {
		if p == "postgres/5432" {
			t.Error("loopback-bound postgres counted as an exposed management port")
		}
	}
}

// A service bound on both the IPv4 and IPv6 wildcard is one exposure, not two.
func TestClassifySockets_DeduplicatesManagementPorts(t *testing.T) {
	_, _, _, management, parts := classifySockets([]listeningSocket{
		{Proto: "tcp", Port: 22, BindAddr: "0.0.0.0"},
		{Proto: "tcp", Port: 22, BindAddr: "::"},
	})

	if management != 1 {
		t.Errorf("management = %d, want 1 — dual-stack bind is a single exposure", management)
	}
	if len(parts) != 1 {
		t.Errorf("parts = %v, want one entry", parts)
	}
}

func TestClassifySockets_Empty(t *testing.T) {
	total, public, loopback, management, parts := classifySockets(nil)
	if total|public|loopback|management != 0 || parts != nil {
		t.Errorf("empty input produced %d/%d/%d/%d %v", total, public, loopback, management, parts)
	}
}

// Zone/scope suffixes are appended by the kernel for interface-bound sockets.
// A wildcard bind carrying one is still a wildcard bind; before stripZone it
// matched neither classifier and vanished from both counters. Observed live
// as "0.0.0.0%virbr0" (dnsmasq on a libvirt bridge).
func TestBindAddrClassification_ZoneSuffixes(t *testing.T) {
	for _, addr := range []string{"0.0.0.0%virbr0", "::%eth0", "0.0.0.0%eth1"} {
		if !isPublicBindAddr(addr) {
			t.Errorf("%q should classify as a public/wildcard bind", addr)
		}
	}
	for _, addr := range []string{"127.0.0.53%lo", "::1%lo", "127.0.0.1%lo"} {
		if !isLoopbackBindAddr(addr) {
			t.Errorf("%q should classify as loopback", addr)
		}
		if isPublicBindAddr(addr) {
			t.Errorf("%q must not classify as public", addr)
		}
	}
	// A link-local address on a real interface is neither wildcard nor loopback.
	if isPublicBindAddr("fe80::1%eth0") || isLoopbackBindAddr("fe80::1%eth0") {
		t.Error("link-local address misclassified")
	}
}

// Every socket must land in exactly one of public/loopback/other, so the
// counters always reconcile against the total.
func TestClassifySockets_CountersReconcile(t *testing.T) {
	sockets := []listeningSocket{
		{Proto: "udp", Port: 67, BindAddr: "0.0.0.0%virbr0"},
		{Proto: "udp", Port: 53, BindAddr: "127.0.0.53%lo"},
		{Proto: "tcp", Port: 22, BindAddr: "0.0.0.0"},
		{Proto: "tcp", Port: 8080, BindAddr: "10.0.0.50"},
	}
	total, public, loopback, _, _ := classifySockets(sockets)
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if public != 2 {
		t.Errorf("public = %d, want 2 (the virbr0 wildcard counts)", public)
	}
	if loopback != 1 {
		t.Errorf("loopback = %d, want 1", loopback)
	}
	if public+loopback > total {
		t.Errorf("counters exceed total: %d + %d > %d", public, loopback, total)
	}
}
