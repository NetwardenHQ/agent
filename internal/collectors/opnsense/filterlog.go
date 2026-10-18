package opnsense

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// filterEvent is one pf log line (OPNsense's filterlog), reduced to the
// fields the metrics use.
type filterEvent struct {
	Interface string
	Action    string // pass, block, reject, ...
	Direction string // in, out
	Src       string
	DstPort   string
}

// parseFilterLog extracts a filterlog record. OPNsense writes RFC 5424 syslog:
//
//	<134>1 2026-10-17T10:00:00-04:00 fw filterlog 123 - [meta sequenceId="1"] 5,,,<tracker>,igc0,match,block,in,4,0x0,,64,1,0,none,6,tcp,60,1.2.3.4,5.6.7.8,40000,22,...
//
// The CSV is the syslog message. Fields 0-8 are common; IPv4 has the addresses
// at 18/19 and ports at 20/21, IPv6 at 15/16 and 17/18.
func parseFilterLog(line []byte) (filterEvent, bool) {
	app, msg, ok := splitSyslog(line)
	if !ok || !bytes.Equal(app, []byte("filterlog")) {
		return filterEvent{}, false
	}
	f := strings.Split(string(bytes.TrimSpace(msg)), ",")
	if len(f) < 9 {
		return filterEvent{}, false
	}
	ev := filterEvent{Interface: f[4], Action: f[6], Direction: f[7]}
	switch f[8] {
	case "4":
		if len(f) > 18 {
			ev.Src = f[18]
		}
		if len(f) > 21 && (f[16] == "tcp" || f[16] == "udp") {
			ev.DstPort = f[21]
		}
	case "6":
		if len(f) > 15 {
			ev.Src = f[15]
		}
		if len(f) > 18 && (f[12] == "tcp" || f[12] == "udp") {
			ev.DstPort = f[18]
		}
	default:
		return filterEvent{}, false
	}
	if ev.Interface == "" || ev.Action == "" {
		return filterEvent{}, false
	}
	return ev, true
}

type filterTally struct {
	blocked, passed map[string]int // by interface
	blockedSrc      map[string]int
	blockedPort     map[string]int
	unparsed        int // non-empty lines that are not a filterlog record
}

func newFilterTally() *filterTally {
	return &filterTally{blocked: map[string]int{}, passed: map[string]int{}, blockedSrc: map[string]int{}, blockedPort: map[string]int{}}
}

// add counts one filterlog line.
func (t *filterTally) add(l []byte) {
	ev, ok := parseFilterLog(l)
	if !ok {
		if len(bytes.TrimSpace(l)) > 0 {
			t.unparsed++
		}
		return
	}
	switch ev.Action {
	case "block", "reject":
		t.blocked[ev.Interface]++
		// Only inbound traffic says anything about who is probing
		// this firewall; outbound blocks are the firewall's own rules.
		if ev.Direction == "in" {
			if addr, err := netip.ParseAddr(ev.Src); err == nil {
				t.blockedSrc[addr.String()]++
			}
			if p, err := strconv.Atoi(ev.DstPort); err == nil && p > 0 && p < 65536 {
				t.blockedPort[strconv.Itoa(p)]++
			}
		}
	case "pass":
		t.passed[ev.Interface]++
	}
}

type ranked struct {
	Key   string
	Count int
}

// topN returns the n largest counts, ties broken by key so output is stable.
func topN(m map[string]int, n int) []ranked {
	r := make([]ranked, 0, len(m))
	for k, v := range m {
		r = append(r, ranked{k, v})
	}
	sort.Slice(r, func(i, j int) bool {
		if r[i].Count != r[j].Count {
			return r[i].Count > r[j].Count
		}
		return r[i].Key < r[j].Key
	})
	if len(r) > n {
		r = r[:n]
	}
	return r
}

// snapshotLabels encodes a top-N list the way the failed-login collector
// does (key_1, count_1, ...), one metric per cycle, so cardinality stays flat.
func snapshotLabels(keyName string, top []ranked) map[string]string {
	labels := map[string]string{}
	for i, r := range top {
		labels[fmt.Sprintf("%s_%d", keyName, i+1)] = r.Key
		labels[fmt.Sprintf("count_%d", i+1)] = fmt.Sprint(r.Count)
	}
	return labels
}

// collectFilterLog turns the pf log into per-interface block and pass counts
// for the interval since the previous cycle.
func (c *Collector) collectFilterLog(_ context.Context, e *emitter) error {
	t := newFilterTally()
	skipped, measured, err := c.filter.each(e.ts, t.add)
	if err != nil || !measured {
		return err
	}
	ifaces := map[string]bool{}
	for i := range t.blocked {
		ifaces[i] = true
	}
	for i := range t.passed {
		ifaces[i] = true
	}
	var totalBlocked, totalPassed int
	for i := range ifaces {
		labels := map[string]string{"interface": i}
		e.gauge("opnsense_filter_blocked", float64(t.blocked[i]), labels)
		e.gauge("opnsense_filter_passed", float64(t.passed[i]), labels)
		totalBlocked += t.blocked[i]
		totalPassed += t.passed[i]
	}
	e.gauge("opnsense_filter_blocked_total_interval", float64(totalBlocked), nil)
	e.gauge("opnsense_filter_passed_total_interval", float64(totalPassed), nil)
	e.gauge("opnsense_filter_blocked_unique_sources", float64(len(t.blockedSrc)), nil)
	if top := topN(t.blockedSrc, 5); len(top) > 0 {
		e.gauge("opnsense_filter_blocked_top_sources", float64(len(top)), snapshotLabels("ip", top))
	}
	if top := topN(t.blockedPort, 5); len(top) > 0 {
		e.gauge("opnsense_filter_blocked_top_ports", float64(len(top)), snapshotLabels("port", top))
	}
	if t.unparsed > 0 {
		e.gauge("opnsense_filter_unparsed_lines", float64(t.unparsed), nil)
	}
	if skipped > 0 {
		e.gauge("opnsense_log_skipped_bytes", float64(skipped), map[string]string{"log": "filter"})
	}
	return nil
}
