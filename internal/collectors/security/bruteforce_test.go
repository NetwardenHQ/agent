package security

import (
	"fmt"
	"testing"
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

func byName(ms []metrics.Metric) map[string][]metrics.Metric {
	out := map[string][]metrics.Metric{}
	for _, m := range ms {
		out[m.Name] = append(out[m.Name], m)
	}
	return out
}

func one(t *testing.T, g map[string][]metrics.Metric, name string) float64 {
	t.Helper()
	if len(g[name]) != 1 {
		t.Fatalf("%s: want one series, got %d", name, len(g[name]))
	}
	return g[name][0].Value
}

var bfNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// A day of background noise: 3 failures every five minutes.
func background(c *AuthCollector) {
	for m := 24 * 60; m > 5; m -= 5 {
		at := bfNow.Add(-time.Duration(m) * time.Minute)
		for i := 0; i < 3; i++ {
			c.recordFailure(fmt.Sprintf("198.51.100.%d", i), at)
		}
	}
}

func TestBackgroundNoiseIsNotABurst(t *testing.T) {
	c := NewAuthCollector("web")
	background(c)
	for i := 0; i < 3; i++ {
		c.recordFailure("198.51.100.1", bfNow.Add(-time.Minute))
	}
	g := byName(c.bruteForceMetrics(bfNow))
	if v := one(t, g, "security_failed_logins_5m"); v != 3 {
		t.Errorf("5m = %v", v)
	}
	if v := one(t, g, "security_failed_logins_usual_5m"); v != 3 {
		t.Errorf("usual = %v", v)
	}
	if v := one(t, g, "security_failed_logins_burst"); v != 0 {
		t.Errorf("background flagged as a burst")
	}
}

func TestBurstAgainstTheHost(t *testing.T) {
	c := NewAuthCollector("web")
	background(c)
	// 60 failures in the last five minutes from 30 addresses: 20x usual.
	for i := 0; i < 60; i++ {
		c.recordFailure(fmt.Sprintf("203.0.113.%d", i%30), bfNow.Add(-time.Duration(i%240)*time.Second))
	}
	g := byName(c.bruteForceMetrics(bfNow))
	if v := one(t, g, "security_failed_logins_burst"); v != 60 {
		t.Errorf("burst = %v", v)
	}
	// Spread across 30 addresses: nobody hammers on their own.
	if v := one(t, g, "security_failed_logins_max_ip_10m"); v != 2 {
		t.Errorf("max per ip = %v", v)
	}
}

func TestBelowTheFloorIsNoBurst(t *testing.T) {
	c := NewAuthCollector("web")
	// A quiet host (nothing all day) with 20 failures: 20x usual, but under 50.
	c.recordFailure("192.0.2.1", bfNow.Add(-24*time.Hour))
	for i := 0; i < 20; i++ {
		c.recordFailure("203.0.113.9", bfNow.Add(-time.Minute))
	}
	g := byName(c.bruteForceMetrics(bfNow))
	if v := one(t, g, "security_failed_logins_burst"); v != 0 {
		t.Errorf("20 failures flagged as a burst")
	}
}

func TestNoBurstWithoutAnHourOfHistory(t *testing.T) {
	c := NewAuthCollector("web")
	for i := 0; i < 80; i++ {
		c.recordFailure("203.0.113.9", bfNow.Add(-time.Minute))
	}
	g := byName(c.bruteForceMetrics(bfNow))
	if len(g["security_failed_logins_usual_5m"]) != 0 {
		t.Errorf("a usual rate claimed from a few minutes of history")
	}
	if v := one(t, g, "security_failed_logins_burst"); v != 0 {
		t.Errorf("burst judged without history")
	}
	// The per-address check needs no history.
	if v := one(t, g, "security_failed_logins_max_ip_10m"); v != 80 {
		t.Errorf("max per ip = %v", v)
	}
}

func TestOneAddressHammering(t *testing.T) {
	c := NewAuthCollector("web")
	for i := 0; i < 55; i++ {
		c.recordFailure("203.0.113.66", bfNow.Add(-time.Duration(i*10)*time.Second))
	}
	for i := 0; i < 12; i++ {
		c.recordFailure("203.0.113.7", bfNow.Add(-time.Minute))
	}
	c.recordFailure("203.0.113.8", bfNow.Add(-time.Minute))
	// Older than ten minutes: not counted.
	for i := 0; i < 40; i++ {
		c.recordFailure("203.0.113.7", bfNow.Add(-30*time.Minute))
	}
	g := byName(c.bruteForceMetrics(bfNow))
	if v := one(t, g, "security_failed_logins_max_ip_10m"); v != 55 {
		t.Errorf("max per ip = %v", v)
	}
	ips := map[string]float64{}
	for _, m := range g["security_failed_logins_ip_10m"] {
		ips[m.Labels["ip"]] = m.Value
	}
	if ips["203.0.113.66"] != 55 || ips["203.0.113.7"] != 12 || len(ips) != 2 {
		t.Errorf("per-ip = %v (addresses under 10 are not named)", ips)
	}
}

func TestFailuresWithoutAnAddressStillCount(t *testing.T) {
	c := NewAuthCollector("win")
	background(c)
	for i := 0; i < 70; i++ {
		c.recordFailure("", bfNow.Add(-time.Minute))
	}
	g := byName(c.bruteForceMetrics(bfNow))
	if v := one(t, g, "security_failed_logins_5m"); v != 70 {
		t.Errorf("5m = %v", v)
	}
}
