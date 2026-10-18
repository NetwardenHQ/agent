package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// gatewayEntry is one value of `configctl interface gateways status`. dpinger
// writes "~" for a figure it does not have.
type gatewayEntry struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Status  string `json:"status"`
	Loss    string `json:"loss"`
	Delay   string `json:"delay"`
	Stddev  string `json:"stddev"`
}

func parseGateways(data []byte) ([]gatewayEntry, error) {
	var m map[string]gatewayEntry
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("gateway status is not valid JSON: %w", err)
	}
	out := make([]gatewayEntry, 0, len(m))
	for name, g := range m {
		if g.Name == "" {
			g.Name = name
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// number parses dpinger's "12.3 ms" / "0.0 %" strings. ok is false for "~",
// empty, or anything that is not a number.
func number(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "~" {
		return 0, false
	}
	f := strings.Fields(s)[0]
	v, err := strconv.ParseFloat(f, 64)
	return v, err == nil
}

func (c *Collector) collectGateways(ctx context.Context, e *emitter) error {
	out, err := c.run(ctx, "/usr/local/sbin/configctl", "interface", "gateways", "status")
	if err != nil {
		return err
	}
	gws, err := parseGateways(out)
	if err != nil {
		return err
	}
	for _, g := range gws {
		labels := map[string]string{"gateway": g.Name, "address": g.Address}
		delay, haveDelay := number(g.Delay)
		loss, haveLoss := number(g.Loss)
		stddev, haveStddev := number(g.Stddev)

		// "none" with no measurements means dpinger has no data for this
		// gateway (monitoring disabled or not started): its state is unknown.
		switch g.Status {
		case "down", "force_down":
			e.gauge("opnsense_gateway_up", 0, labels)
		case "none", "delay", "loss", "delay+loss":
			if g.Status == "none" && !haveDelay && !haveLoss {
				break
			}
			e.gauge("opnsense_gateway_up", 1, labels)
			e.gauge("opnsense_gateway_degraded", b2f(g.Status != "none"), labels)
		}
		if g.Status == "force_down" {
			e.gauge("opnsense_gateway_forced_down", 1, labels)
		}
		if haveDelay {
			e.gauge("opnsense_gateway_latency_ms", delay, labels)
		}
		if haveStddev {
			e.gauge("opnsense_gateway_jitter_ms", stddev, labels)
		}
		if haveLoss {
			e.gauge("opnsense_gateway_loss_percent", loss, labels)
		}
	}
	return nil
}
