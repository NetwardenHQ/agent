//go:build freebsd

package security

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// portsSource labels the metrics with where the sockets came from.
const portsSource = "sockstat"

// collectListeningSockets lists listening TCP and UDP sockets with sockstat(1),
// which is part of the FreeBSD base system. gopsutil's FreeBSD connection
// listing needs lsof, which base FreeBSD lacks.
func collectListeningSockets(ctx context.Context) ([]listeningSocket, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sockstat", "-46l", "-P", "tcp,udp").Output()
	if err != nil {
		return nil, fmt.Errorf("sockstat: %w", err)
	}
	return parseSockstat(out), nil
}
