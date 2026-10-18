package opnsense

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type eveEvent struct {
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	Alert     struct {
		Action      string      `json:"action"`
		SignatureID json.Number `json:"signature_id"`
		Signature   string      `json:"signature"`
		Category    string      `json:"category"`
		Severity    json.Number `json:"severity"`
	} `json:"alert"`
	Stats struct {
		// Pointers: some capture modes write a stats record without these
		// counters, and an absent counter must not be reported as 0.
		Capture struct {
			KernelPackets *float64 `json:"kernel_packets"`
			KernelDrops   *float64 `json:"kernel_drops"`
		} `json:"capture"`
	} `json:"stats"`
}

type idsTally struct {
	alerts, blocked int
	bySeverity      map[string]int
	srcs            map[string]int
	sigs            map[string]int
	sigNames        map[string]string
	stats           *eveEvent // the newest stats record in the interval
	bad             int       // lines that were not valid JSON
}

func newIDSTally() *idsTally {
	return &idsTally{bySeverity: map[string]int{}, srcs: map[string]int{}, sigs: map[string]int{}, sigNames: map[string]string{}}
}

// add counts one eve.json line.
func (t *idsTally) add(l []byte) {
	l = bytes.TrimSpace(l)
	if len(l) == 0 {
		return
	}
	var ev eveEvent
	if err := json.Unmarshal(l, &ev); err != nil {
		t.bad++
		return
	}
	switch ev.EventType {
	case "alert":
		t.alerts++
		if ev.Alert.Action == "blocked" {
			t.blocked++
		}
		sev := ev.Alert.Severity.String()
		if sev == "" {
			sev = "unknown"
		}
		t.bySeverity[sev]++
		if addr, err := netip.ParseAddr(ev.SrcIP); err == nil {
			t.srcs[addr.String()]++
		}
		id := ev.Alert.SignatureID.String()
		t.sigs[id]++
		t.sigNames[id] = ev.Alert.Signature
	case "stats":
		t.stats = &ev
	}
}

// suricataRunning checks the pid file and that the process answers signal 0.
func (c *Collector) suricataRunning() (bool, error) {
	raw, err := os.ReadFile(c.suricataPID)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return false, fmt.Errorf("suricata pid file %s is malformed", c.suricataPID)
	}
	return processAlive(pid)
}

// collectIDS reports Suricata. When the GUI has the IDS switched off it
// reports that and nothing else; when it is on, a stopped process is the
// most important signal.
func (c *Collector) collectIDS(_ context.Context, e *emitter) error {
	if c.cfg == nil {
		return fmt.Errorf("IDS configuration unknown: config.xml could not be read this cycle")
	}
	e.gauge("opnsense_ids_enabled", b2f(c.cfg.IDSEnabled), nil)
	if !c.cfg.IDSEnabled {
		return nil
	}
	e.gauge("opnsense_ids_ips_mode", b2f(c.cfg.IPSMode), nil)

	running, err := c.suricataRunning()
	if err != nil {
		return err
	}
	e.gauge("opnsense_ids_running", b2f(running), nil)

	t := newIDSTally()
	skipped, measured, err := c.eve.each(e.ts, t.add)
	if err != nil {
		return err
	}
	if !measured {
		return nil
	}
	e.gauge("opnsense_ids_alerts", float64(t.alerts), nil)
	e.gauge("opnsense_ids_blocked", float64(t.blocked), nil)
	for _, sev := range []string{"1", "2", "3"} {
		e.gauge("opnsense_ids_alerts_by_severity", float64(t.bySeverity[sev]), map[string]string{"severity": sev})
	}
	e.gauge("opnsense_ids_unique_sources", float64(len(t.srcs)), nil)
	if top := topN(t.srcs, 5); len(top) > 0 {
		e.gauge("opnsense_ids_top_sources", float64(len(top)), snapshotLabels("ip", top))
	}
	for _, s := range topN(t.sigs, 5) {
		e.gauge("opnsense_ids_top_signature", float64(s.Count), map[string]string{
			"signature_id": s.Key, "signature": truncate(t.sigNames[s.Key], 120),
		})
	}
	if t.stats != nil {
		// Suricata's own counters since it started; a rising drop count
		// means the box cannot keep up with its traffic.
		if v := t.stats.Stats.Capture.KernelPackets; v != nil {
			e.gauge("opnsense_ids_kernel_packets", *v, nil)
		}
		if v := t.stats.Stats.Capture.KernelDrops; v != nil {
			e.gauge("opnsense_ids_kernel_drops", *v, nil)
		}
	}
	if t.bad > 0 {
		e.gauge("opnsense_ids_unparsed_lines", float64(t.bad), nil)
	}
	if skipped > 0 {
		e.gauge("opnsense_log_skipped_bytes", float64(skipped), map[string]string{"log": "eve"})
	}
	return nil
}
