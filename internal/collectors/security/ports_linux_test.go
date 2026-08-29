//go:build linux

package security

import "testing"

// Real `ss -tulnpH` output (two socket families requested → Netid column
// present). Captured from Ubuntu 24.04, iproute2 6.1.
const ssNetidFirst = `tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=1234,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:5432      0.0.0.0:*    users:(("postgres",pid=987,fd=5))
tcp   LISTEN 0      511             [::]:80           [::]:*    users:(("nginx",pid=555,fd=6),("nginx",pid=556,fd=6))
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=321,fd=12))
tcp   ESTAB  0      0          10.0.0.5:44321     10.0.0.9:443
`

// Real `ss -tlnpH` output (ONE socket family requested → ss OMITS the Netid
// column and the row starts at State). This is the layout that previously
// parsed to zero sockets, silently reporting the host as having no open ports.
const ssStateFirst = `LISTEN 0      4096         0.0.0.0:22       0.0.0.0:*   users:(("sshd",pid=1234,fd=3))
LISTEN 0      4096       127.0.0.1:5432     0.0.0.0:*   users:(("postgres",pid=987,fd=5))
LISTEN 0      511             [::]:80          [::]:*   users:(("nginx",pid=555,fd=6))
`

func findSocket(t *testing.T, got []listeningSocket, proto string, port int) listeningSocket {
	t.Helper()
	for _, s := range got {
		if s.Proto == proto && s.Port == port {
			return s
		}
	}
	t.Fatalf("no %s socket on port %d in %+v", proto, port, got)
	return listeningSocket{}
}

func TestParseSSOutput_NetidFirstLayout(t *testing.T) {
	got := parseSSOutput(ssNetidFirst, protoTCP)

	// 3 LISTEN + 1 UDP UNCONN. The ESTAB row must be dropped.
	if len(got) != 4 {
		t.Fatalf("expected 4 sockets, got %d: %+v", len(got), got)
	}

	ssh := findSocket(t, got, protoTCP, 22)
	if ssh.BindAddr != "0.0.0.0" || ssh.ProcessName != "sshd" || ssh.PID != 1234 {
		t.Errorf("sshd row mis-parsed: %+v", ssh)
	}

	pg := findSocket(t, got, protoTCP, 5432)
	if pg.BindAddr != "127.0.0.1" || pg.ProcessName != "postgres" || pg.PID != 987 {
		t.Errorf("postgres row mis-parsed: %+v", pg)
	}

	// IPv6 wildcard + multiple users:(...) entries — first one wins.
	ngx := findSocket(t, got, protoTCP, 80)
	if ngx.BindAddr != "::" || ngx.ProcessName != "nginx" || ngx.PID != 555 {
		t.Errorf("nginx row mis-parsed: %+v", ngx)
	}

	dns := findSocket(t, got, protoUDP, 53)
	if dns.BindAddr != "127.0.0.53%lo" || dns.ProcessName != "systemd-resolve" {
		t.Errorf("udp row mis-parsed: %+v", dns)
	}

	for _, s := range got {
		if s.Proto == protoTCP && s.Port == 44321 {
			t.Errorf("ESTAB connection leaked into listening set: %+v", s)
		}
	}
}

// Regression test for the silent-zero bug: `ss -tlnpH` omits Netid, so every
// row began with "LISTEN" rather than "tcp" and the parser skipped all of
// them — a host with exposed ports reported as having none.
func TestParseSSOutput_StateFirstLayout(t *testing.T) {
	got := parseSSOutput(ssStateFirst, protoTCP)

	if len(got) != 3 {
		t.Fatalf("state-first layout parsed %d sockets, want 3: %+v", len(got), got)
	}

	ssh := findSocket(t, got, protoTCP, 22)
	if ssh.BindAddr != "0.0.0.0" || ssh.ProcessName != "sshd" || ssh.PID != 1234 {
		t.Errorf("sshd row mis-parsed: %+v", ssh)
	}
	if s := findSocket(t, got, protoTCP, 80); s.BindAddr != "::" {
		t.Errorf("ipv6 bind mis-parsed: %+v", s)
	}
	for _, s := range got {
		if s.Proto != protoTCP {
			t.Errorf("defaultProto not applied, got %q: %+v", s.Proto, s)
		}
	}
}

// A public bind on a management port is the finding that matters most; make
// sure it survives the parse in both layouts.
func TestParseSSOutput_PublicManagementPortDetected(t *testing.T) {
	for name, out := range map[string]string{
		"netid-first": ssNetidFirst,
		"state-first": ssStateFirst,
	} {
		t.Run(name, func(t *testing.T) {
			ssh := findSocket(t, parseSSOutput(out, protoTCP), protoTCP, 22)
			if !isPublicBindAddr(ssh.BindAddr) {
				t.Fatalf("ssh on %s not classified as public bind", ssh.BindAddr)
			}
			if _, ok := managementPorts[ssh.Port]; !ok {
				t.Fatalf("port 22 missing from managementPorts")
			}
		})
	}
}

func TestParseSSOutput_NoProcessInfo(t *testing.T) {
	// Non-root agent: ss omits the users:(...) column entirely.
	const out = `tcp   LISTEN 0      4096   0.0.0.0:22   0.0.0.0:*
LISTEN 0      4096   0.0.0.0:443  0.0.0.0:*
`
	got := parseSSOutput(out, protoTCP)
	if len(got) != 2 {
		t.Fatalf("expected 2 sockets, got %d: %+v", len(got), got)
	}
	for _, s := range got {
		if s.ProcessName != "" || s.PID != 0 {
			t.Errorf("expected redacted process info, got %+v", s)
		}
	}
}

func TestParseSSOutput_SkipsHeadersAndJunk(t *testing.T) {
	const out = `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
State  Recv-Q Send-Q Local Address:Port Peer Address:Port

garbage line that is not a socket
tcp   LISTEN 0      4096   0.0.0.0:22   0.0.0.0:*
`
	if got := parseSSOutput(out, protoTCP); len(got) != 1 {
		t.Fatalf("expected 1 socket, got %d: %+v", len(got), got)
	}
}

const netstatOut = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp6       0      0 :::80                   :::*                    LISTEN      555/nginx
tcp        0      0 10.0.0.5:44321          10.0.0.9:443            ESTABLISHED 777/curl
udp        0      0 0.0.0.0:68              0.0.0.0:*                           321/dhclient
udp        0      0 0.0.0.0:123             0.0.0.0:*                           -
`

func TestParseNetstatOutput(t *testing.T) {
	got := parseNetstatOutput(netstatOut)

	// 2 LISTEN + 2 UDP; ESTABLISHED must be dropped.
	if len(got) != 4 {
		t.Fatalf("expected 4 sockets, got %d: %+v", len(got), got)
	}

	ssh := findSocket(t, got, protoTCP, 22)
	if ssh.BindAddr != "0.0.0.0" || ssh.ProcessName != "sshd" || ssh.PID != 1234 {
		t.Errorf("sshd row mis-parsed: %+v", ssh)
	}

	// tcp6 must normalize to "tcp" — the platform contract accepts only
	// "tcp"/"udp", and the address family is evident from the bind address.
	ngx := findSocket(t, got, protoTCP, 80)
	if ngx.BindAddr != "::" || ngx.ProcessName != "nginx" {
		t.Errorf("tcp6 row mis-parsed: %+v", ngx)
	}

	// Redacted process column ("-") must not corrupt the row.
	ntp := findSocket(t, got, protoUDP, 123)
	if ntp.ProcessName != "" || ntp.PID != 0 {
		t.Errorf("redacted process info mis-parsed: %+v", ntp)
	}
}

func TestSplitHostPort(t *testing.T) {
	for _, tc := range []struct {
		in   string
		addr string
		port int
		ok   bool
	}{
		{"0.0.0.0:22", "0.0.0.0", 22, true},
		{"127.0.0.1:5432", "127.0.0.1", 5432, true},
		{"[::]:80", "::", 80, true},
		{"[::1]:631", "::1", 631, true},
		{"[fe80::1%eth0]:546", "fe80::1%eth0", 546, true},
		{"*:22", "*", 22, true},
		{"127.0.0.53%lo:53", "127.0.0.53%lo", 53, true},
		{"0.0.0.0:*", "", 0, false},
		{"garbage", "", 0, false},
		{":22", "", 0, false},
		{"0.0.0.0:", "", 0, false},
	} {
		addr, port, ok := splitHostPort(tc.in)
		if ok != tc.ok || (ok && (addr != tc.addr || port != tc.port)) {
			t.Errorf("splitHostPort(%q) = (%q,%d,%v), want (%q,%d,%v)",
				tc.in, addr, port, ok, tc.addr, tc.port, tc.ok)
		}
	}
}

func TestParseSSUsersField(t *testing.T) {
	for _, tc := range []struct {
		in   string
		name string
		pid  int
	}{
		{`users:(("sshd",pid=1234,fd=3))`, "sshd", 1234},
		{`users:(("postgres",pid=987,fd=5),("postgres",pid=988,fd=6))`, "postgres", 987},
		{`users:(("my app",pid=42,fd=9))`, "my app", 42},
		{`users:(("nofd",pid=7))`, "nofd", 7},
		{``, "", 0},
		{`not-a-users-field`, "", 0},
	} {
		name, pid := parseSSUsersField(tc.in)
		if name != tc.name || pid != tc.pid {
			t.Errorf("parseSSUsersField(%q) = (%q,%d), want (%q,%d)", tc.in, name, pid, tc.name, tc.pid)
		}
	}
}

func TestBindAddrClassification(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "::", "*", ""} {
		if !isPublicBindAddr(addr) {
			t.Errorf("%q should be public", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1", "::1", "127.0.0.53"} {
		if !isLoopbackBindAddr(addr) {
			t.Errorf("%q should be loopback", addr)
		}
		if isPublicBindAddr(addr) {
			t.Errorf("%q must not be public", addr)
		}
	}
	if isPublicBindAddr("10.0.0.5") || isLoopbackBindAddr("10.0.0.5") {
		t.Error("specific LAN IP is neither public-wildcard nor loopback")
	}
}
