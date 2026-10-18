package opnsense

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

var carpRe = regexp.MustCompile(`(?m)^\s+carp:\s+(MASTER|BACKUP|INIT)\s+vhid\s+\d+`)

// countCARP returns the number of virtual hosts per state in `ifconfig -a`.
func countCARP(ifconfig string) map[string]int {
	counts := map[string]int{}
	for _, m := range carpRe.FindAllStringSubmatch(ifconfig, -1) {
		counts[strings.ToLower(m[1])]++
	}
	return counts
}

// collectCARP reports high-availability state. A firewall with no CARP
// virtual addresses is not an HA pair and reports nothing here.
func (c *Collector) collectCARP(ctx context.Context, e *emitter) error {
	out, err := c.run(ctx, "/sbin/ifconfig", "-a")
	if err != nil {
		return err
	}
	counts := countCARP(string(out))
	if len(counts) == 0 {
		return nil
	}
	for _, state := range []string{"master", "backup", "init"} {
		e.gauge("opnsense_carp_vhids", float64(counts[state]), map[string]string{"state": state})
	}
	dem, err := c.run(ctx, "/sbin/sysctl", "-n", "net.inet.carp.demotion")
	if err != nil {
		return err
	}
	if v, perr := strconv.ParseFloat(strings.TrimSpace(string(dem)), 64); perr == nil {
		// A non-zero demotion means CARP detected a fault and this unit
		// is giving up its MASTER role.
		e.gauge("opnsense_carp_demotion", v, nil)
	}
	return nil
}
