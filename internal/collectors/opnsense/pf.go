package opnsense

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	pfEnabledRe = regexp.MustCompile(`(?m)^Status:\s+(Enabled|Disabled)`)
	pfCounterRe = regexp.MustCompile(`(?m)^\s+(current entries|searches|inserts|removals)\s+(\d+)`)
	pfLimitRe   = regexp.MustCompile(`(?m)^states\s+hard limit\s+(\d+)`)
	pfMatchRe   = regexp.MustCompile(`(?m)^\s+(match|bad-offset|fragment|short|normalize|memory|bad-timestamp|congestion|ip-option|proto-cksum|state-mismatch|state-insert|state-limit|src-limit|synproxy|map-failed)\s+(\d+)`)
)

type pfInfo struct {
	Enabled        bool
	Counters       map[string]float64 // current entries, searches, inserts, removals
	PacketCounters map[string]float64
}

func parsePFInfo(out string) (pfInfo, error) {
	m := pfEnabledRe.FindStringSubmatch(out)
	if m == nil {
		return pfInfo{}, fmt.Errorf("pfctl -si output has no Status line")
	}
	info := pfInfo{Enabled: m[1] == "Enabled", Counters: map[string]float64{}, PacketCounters: map[string]float64{}}
	for _, m := range pfCounterRe.FindAllStringSubmatch(out, -1) {
		v, _ := strconv.ParseFloat(m[2], 64)
		info.Counters[m[1]] = v
	}
	for _, m := range pfMatchRe.FindAllStringSubmatch(out, -1) {
		v, _ := strconv.ParseFloat(m[2], 64)
		info.PacketCounters[m[1]] = v
	}
	if _, ok := info.Counters["current entries"]; !ok {
		return pfInfo{}, fmt.Errorf("pfctl -si output has no state table counters")
	}
	return info, nil
}

func parsePFStateLimit(out string) (float64, bool) {
	m := pfLimitRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	return v, err == nil && v > 0
}

// collectPF reports the packet filter's state table, the number that decides
// whether a busy firewall starts dropping new connections.
func (c *Collector) collectPF(ctx context.Context, e *emitter) error {
	out, err := c.run(ctx, "/sbin/pfctl", "-si")
	if err != nil {
		return err
	}
	info, err := parsePFInfo(string(out))
	if err != nil {
		return err
	}
	e.gauge("opnsense_pf_enabled", b2f(info.Enabled), nil)
	states := info.Counters["current entries"]
	e.gauge("opnsense_pf_states", states, nil)
	e.gauge("opnsense_pf_state_searches_total", info.Counters["searches"], nil)
	e.gauge("opnsense_pf_state_inserts_total", info.Counters["inserts"], nil)
	e.gauge("opnsense_pf_state_removals_total", info.Counters["removals"], nil)
	for name, v := range info.PacketCounters {
		e.gauge("opnsense_pf_counter_total", v, map[string]string{"counter": strings.ReplaceAll(name, "-", "_")})
	}

	// The state limit comes from a second command; without it the table
	// usage percentage would be a guess, so it is not reported.
	if lim, lerr := c.run(ctx, "/sbin/pfctl", "-sm"); lerr == nil {
		if limit, ok := parsePFStateLimit(string(lim)); ok {
			e.gauge("opnsense_pf_states_limit", limit, nil)
			e.gauge("opnsense_pf_state_usage_percent", states/limit*100, nil)
		}
	} else {
		c.warnOnce("pf-limit", lerr)
	}
	return nil
}
