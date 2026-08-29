package cis

import (
	"strings"
	"testing"
)

// Minimum per-section coverage. These are floors, not targets — they exist so
// a refactor cannot silently drop a whole benchmark domain. Raise them as
// coverage grows; never lower one to make a failing build pass.
var minCoverage = map[string]struct{ l1, l2 int }{
	"1": {40, 10}, // Initial setup: modules, partitions, SELinux, banners
	"2": {25, 5},  // Services
	"3": {10, 8},  // Network
	"4": {2, 0},   // Firewall
	"5": {30, 12}, // Access control
	"6": {4, 25},  // Logging and auditing — L2-heavy by nature
	"7": {20, 2},  // System maintenance
}

func TestCatalogCoveragePerSection(t *testing.T) {
	bySection := map[string]struct{ l1, l2 int }{}
	for _, c := range Catalog() {
		top := strings.SplitN(c.Section, ".", 2)[0]
		v := bySection[top]
		if c.Level == 1 {
			v.l1++
		} else {
			v.l2++
		}
		bySection[top] = v
	}

	for section, want := range minCoverage {
		got := bySection[section]
		t.Logf("section %s: L1=%2d L2=%2d (floor L1>=%d L2>=%d)", section, got.l1, got.l2, want.l1, want.l2)
		if got.l1 < want.l1 {
			t.Errorf("section %s: L1 coverage dropped to %d, floor is %d", section, got.l1, want.l1)
		}
		if got.l2 < want.l2 {
			t.Errorf("section %s: L2 coverage dropped to %d, floor is %d", section, got.l2, want.l2)
		}
	}
}
