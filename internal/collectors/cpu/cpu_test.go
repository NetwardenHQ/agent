package cpu

import (
	"testing"

	"github.com/shirou/gopsutil/v4/cpu"
)

func TestBusyPercent(t *testing.T) {
	prev := cpu.TimesStat{User: 100, System: 50, Idle: 800, Iowait: 50}

	tests := []struct {
		name string
		now  cpu.TimesStat
		want float64
		ok   bool
	}{
		{"half busy", cpu.TimesStat{User: 150, System: 50, Idle: 850, Iowait: 50}, 50, true},
		{"idle", cpu.TimesStat{User: 100, System: 50, Idle: 900, Iowait: 50}, 0, true},
		{"iowait counts as idle", cpu.TimesStat{User: 100, System: 50, Idle: 800, Iowait: 150}, 0, true},
		{"fully busy", cpu.TimesStat{User: 200, System: 50, Idle: 800, Iowait: 50}, 100, true},
		// No elapsed CPU time is unknown, not 0% busy.
		{"no elapsed time", prev, 0, false},
		{"counter went backwards", cpu.TimesStat{User: 50, System: 50, Idle: 800, Iowait: 50}, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := busyPercent(prev, tc.now)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Errorf("busyPercent = %v, %v; want %v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
