package security

import "testing"

func TestParseSockstat(t *testing.T) {
	out := []byte(`USER COMMAND     PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
root sshd       1261  6 tcp6  *:22                  *:*
root sshd       1261  7 tcp4  *:22                  *:*
root unbound     810  4 udp4  127.0.0.1:53           *:*
?    ?             ?  ? tcp4  10.0.0.1:443           *:*
root junk        1 2 raw4 *:1 *:*
`)
	got := parseSockstat(out)
	if len(got) != 4 {
		t.Fatalf("got %d sockets, want 4: %+v", len(got), got)
	}
	if got[0].BindAddr != "::" || got[1].BindAddr != "0.0.0.0" || got[2].BindAddr != "127.0.0.1" || got[2].Proto != protoUDP {
		t.Fatalf("wrong addresses/protocols: %+v", got)
	}
	if got[3].ProcessName != "" || got[3].Port != 443 {
		t.Fatalf("unknown owner should have empty name: %+v", got[3])
	}
}

// A process name containing spaces cannot plant a fake listener row.
func TestParseSockstat_CommandWithSpacesCannotSpoof(t *testing.T) {
	out := []byte(`USER COMMAND     PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
bob  x 1 2 tcp4 *:31337 *:* 4242 5 udp4 127.0.0.1:5353 *:*
root my daemon   900  3 tcp4  *:8080                *:*
`)
	got := parseSockstat(out)
	if len(got) != 2 {
		t.Fatalf("got %d sockets, want 2: %+v", len(got), got)
	}
	if got[0].Port != 5353 || got[0].Proto != protoUDP || got[0].PID != 4242 || got[0].BindAddr != "127.0.0.1" {
		t.Fatalf("spoofed row parsed wrong: %+v", got[0])
	}
	if got[0].ProcessName != "x 1 2 tcp4 *:31337 *:*" {
		t.Fatalf("process name = %q", got[0].ProcessName)
	}
	if got[1].ProcessName != "my daemon" || got[1].PID != 900 || got[1].Port != 8080 {
		t.Fatalf("spaced name parsed wrong: %+v", got[1])
	}
}
