package security

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// sockstat parsing lives in an untagged file so its tests run on every
// build host; only ports_source_freebsd.go calls it.

// parseSockstat parses `sockstat -46l -P tcp,udp`:
//
//	USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
//	root sshd    1261 6 tcp6  *:22          *:*
//
// Rows it cannot read are skipped. Sockets owned by other users show as "?"
// for the process when the agent is not root.
//
// COMMAND is chosen by whoever started the process and can contain spaces,
// so the fixed columns are read from the right and everything between USER
// and PID is the name; otherwise a process named "x 1 2 tcp4 *:31337 *:*"
// could plant a fake listener. These flags add no other columns (-s, -i, -S,
// -C and -U would). sockstat --libxo is not used because it first appeared in
// FreeBSD 15.
func parseSockstat(out []byte) []listeningSocket {
	var sockets []listeningSocket
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		n := len(f)
		if n < 7 || f[0] == "USER" {
			continue
		}
		pidField, protoField, local := f[n-5], f[n-3], f[n-2]
		proto, v6 := "", false
		switch protoField {
		case "tcp4":
			proto = protoTCP
		case "tcp6":
			proto, v6 = protoTCP, true
		case "udp4":
			proto = protoUDP
		case "udp6":
			proto, v6 = protoUDP, true
		default:
			continue
		}
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		addr := local[:i]
		switch {
		case addr == "*" && v6:
			addr = "::"
		case addr == "*":
			addr = "0.0.0.0"
		}
		pid, _ := strconv.Atoi(pidField) // "?" when not visible: 0, no PID
		name := strings.Join(f[1:n-5], " ")
		if name == "?" {
			name = ""
		}
		sockets = append(sockets, listeningSocket{
			Proto: proto, Port: port, BindAddr: addr, ProcessName: name, PID: pid,
		})
	}
	return sockets
}
