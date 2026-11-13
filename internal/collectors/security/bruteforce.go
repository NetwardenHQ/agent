package security

import (
	"sort"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Brute-force signals. Each collection reports failures for its own window,
// and the transmitter does not resend a value that did not change, so the
// platform cannot add windows up. These are rolling levels instead, true
// whenever they were last sent:
//
//	security_failed_logins_5m           failures in the last five minutes
//	security_failed_logins_usual_5m     the median five-minute count over the last day
//	security_failed_logins_burst        the five-minute count when it is a burst, else 0
//	security_failed_logins_max_ip_10m   the most failures from one address in ten minutes
//	security_failed_logins_ip_10m{ip}   per address, for those with ten or more
//
// A burst is at least burstFloor failures in five minutes and at least
// burstFactor times this host's usual count. An internet-facing SSH server
// sees a steady trickle of guesses all day; only a sharp rise above its own
// normal is an attack on this host.
const (
	burstFloor     = 50
	burstFactor    = 10
	slot           = 5 * time.Minute
	historySlots   = 288 // a day of five-minute slots
	minHistory     = 12  // an hour, before "usual" means anything
	ipWindow       = 10 * time.Minute
	namedIPMinimum = 10
	namedIPs       = 5
)

// recordFailure notes one failed login, from ip when the log names one.
func (c *AuthCollector) recordFailure(ip string, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	minute := at.Truncate(time.Minute).Unix()
	c.perMinute[minute]++
	if c.firstFailure.IsZero() || at.Before(c.firstFailure) {
		c.firstFailure = at
	}
	if ip != "" {
		c.failures.add(ip, at)
	}
}

// bruteForceMetrics reports the rolling levels as of now.
func (c *AuthCollector) bruteForceMetrics(now time.Time) []metrics.Metric {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Drop minutes older than the history needs.
	oldest := now.Add(-time.Duration(historySlots+1) * slot).Unix()
	for m := range c.perMinute {
		if m < oldest {
			delete(c.perMinute, m)
		}
	}

	var slots [historySlots + 1]int
	for m, n := range c.perMinute {
		age := now.Sub(time.Unix(m, 0))
		if age < 0 {
			age = 0
		}
		if k := int(age / slot); k <= historySlots {
			slots[k] += n
		}
	}
	current := slots[0]

	// History counts from when the agent started watching, or from the
	// oldest failure it has read, whichever is earlier.
	start := c.started
	if !c.firstFailure.IsZero() && c.firstFailure.Before(start) {
		start = c.firstFailure
	}
	known := int(now.Sub(start) / slot)
	if known > historySlots {
		known = historySlots
	}

	var out []metrics.Metric
	ts := now
	c.addGauge(&out, "security_failed_logins_5m", float64(current), ts)
	burst := 0
	if known >= minHistory {
		past := append([]int(nil), slots[1:known+1]...)
		sort.Ints(past)
		usual := past[len(past)/2]
		c.addGauge(&out, "security_failed_logins_usual_5m", float64(usual), ts)
		if current >= burstFloor && current >= burstFactor*usual {
			burst = current
		}
	}
	c.addGauge(&out, "security_failed_logins_burst", float64(burst), ts)

	type ipCount struct {
		ip string
		n  int
	}
	var counts []ipCount
	for ip, times := range c.failures.byIP {
		n := 0
		for _, t := range times {
			if t.After(now.Add(-ipWindow)) && !t.After(now) {
				n++
			}
		}
		if n > 0 {
			counts = append(counts, ipCount{ip, n})
		}
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].n != counts[j].n {
			return counts[i].n > counts[j].n
		}
		return counts[i].ip < counts[j].ip
	})
	maxIP := 0
	if len(counts) > 0 {
		maxIP = counts[0].n
	}
	c.addGauge(&out, "security_failed_logins_max_ip_10m", float64(maxIP), ts)
	for i, ic := range counts {
		if i >= namedIPs || ic.n < namedIPMinimum {
			break
		}
		c.addGaugeWithLabels(&out, "security_failed_logins_ip_10m", float64(ic.n), map[string]string{"ip": ic.ip}, ts)
	}
	return out
}
