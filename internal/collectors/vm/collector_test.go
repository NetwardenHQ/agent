//go:build linux

package vm

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/NetwardenHQ/agent/internal/config"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeHypervisor serves a fixed inventory and fixed stats.
type fakeHypervisor struct {
	vms   []VM
	stats *VMStats
}

func (f *fakeHypervisor) Name() string                          { return "fake" }
func (f *fakeHypervisor) IsAvailable() bool                     { return true }
func (f *fakeHypervisor) ListVMs(context.Context) ([]VM, error) { return f.vms, nil }
func (f *fakeHypervisor) GetVMStats(context.Context, VM) (*VMStats, error) {
	s := *f.stats
	return &s, nil
}
func (f *fakeHypervisor) Close() error { return nil }

// seriesFor returns the value of name for the VM called vm, and whether the
// series exists.
func seriesFor(ms []metrics.Metric, name, vm string) (float64, bool) {
	for _, m := range ms {
		if m.Name == name && m.Labels["vm"] == vm {
			return m.Value, true
		}
	}
	return 0, false
}

func newTestCollector(t *testing.T, h HypervisorClient) *Collector {
	t.Helper()
	return &Collector{
		hostname:   "test-" + strings.ReplaceAll(t.Name(), "/", "_"),
		logger:     quietLogger(),
		builder:    metrics.NewBuilder().WithHostname("h"),
		enabled:    true,
		config:     config.VMConfig{VMTimeout: time.Second, VMParallelStats: 2},
		hypervisor: h,
	}
}

// vm_status encodes 0 stopped, 1 running, 2 paused. An unrecognized state
// gets no vm_status, since 0 would report it as stopped.
func TestCollect_StatusEncodingAndUnknownInventory(t *testing.T) {
	h := &fakeHypervisor{
		vms: []VM{
			{ID: "1", Name: "run", Status: "running", CPUCount: 2, MemoryMB: 1024},
			{ID: "2", Name: "stop", Status: "stopped", CPUCount: 2, MemoryMB: 1024},
			{ID: "3", Name: "pause", Status: "paused", CPUCount: 2, MemoryMB: 1024},
			{ID: "4", Name: "odd", Status: "crashed"}, // XML unreadable: no vCPU/memory
		},
		stats: &VMStats{},
	}
	ms, err := newTestCollector(t, h).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for vm, want := range map[string]float64{"run": 1, "stop": 0, "pause": 2} {
		if v, ok := seriesFor(ms, "vm_status", vm); !ok || v != want {
			t.Errorf("vm_status{%s} = %v (present %v), want %v", vm, v, ok, want)
		}
	}
	for _, name := range []string{"vm_status", "vm_cpu_count", "vm_memory_mb"} {
		if v, ok := seriesFor(ms, name, "odd"); ok {
			t.Errorf("%s{odd} = %v; unknown must be omitted", name, v)
		}
	}
}

// Host-view memory is only reported when the hypervisor said something.
func TestCollectVMStats_OmitsUnknownHostMemory(t *testing.T) {
	c := newTestCollector(t, &fakeHypervisor{})
	var out []metrics.Metric
	c.collectVMStats(&VMStats{CPUTime: 1}, map[string]string{"vm": "x"}, &out)
	for _, name := range []string{"vm_memory_usage_mb", "vm_memory_available_mb", "vm_memory_usage_percent"} {
		if _, ok := seriesFor(out, name, "x"); ok {
			t.Errorf("%s emitted without any memory figure from the hypervisor", name)
		}
	}
}

// proxmoxServer requires the API token on every path, as PVE does.
func proxmoxServer(t *testing.T, statusJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=root@pam!nw=secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api2/json/version":
			_, _ = io.WriteString(w, `{"data":{"version":"8.2"}}`)
		case strings.HasSuffix(r.URL.Path, "/status/current"):
			_, _ = io.WriteString(w, statusJSON)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func proxmoxConfig(api string) config.VMConfig {
	return config.VMConfig{
		ProxmoxAPI:         api,
		ProxmoxTokenID:     "root@pam!nw",
		ProxmoxTokenSecret: "secret",
		VMTimeout:          5 * time.Second,
	}
}

// PVE answers 401 to an unauthenticated /version, so the probe must
// authenticate.
func TestProxmox_IsAvailableAuthenticates(t *testing.T) {
	srv := proxmoxServer(t, `{"data":{}}`)
	defer srv.Close()
	p := NewProxmoxClient(proxmoxConfig(srv.URL), quietLogger())
	if !p.IsAvailable() {
		t.Fatal("reachable, correctly authenticated API reported unavailable")
	}
}

// A guest over its ceiling must not report negative headroom.
func TestProxmox_MemoryAvailableNeverNegative(t *testing.T) {
	srv := proxmoxServer(t, `{"data":{"cpu":0.1,"mem":3221225472,"maxmem":2147483648}}`)
	defer srv.Close()
	p := NewProxmoxClient(proxmoxConfig(srv.URL), quietLogger())
	s, err := p.GetVMStats(context.Background(), VM{ID: "100", Node: "pve", VMID: 100})
	if err != nil {
		t.Fatal(err)
	}
	if s.MemoryAvailableMB < 0 {
		t.Errorf("MemoryAvailableMB = %d", s.MemoryAvailableMB)
	}
}

// Concurrent stats requests authenticate and read the auth header at the same
// time; run with -race.
func TestProxmox_ConcurrentRequests(t *testing.T) {
	srv := proxmoxServer(t, `{"data":{"mem":1,"maxmem":2}}`)
	defer srv.Close()
	p := NewProxmoxClient(proxmoxConfig(srv.URL), quietLogger())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.GetVMStats(context.Background(), VM{ID: "100", Node: "pve", VMID: 100}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

// Without balloon.rss or balloon.current there is no host-view memory.
func TestParseDomainStats_NoBalloonMeansNoMemory(t *testing.T) {
	s := parseDomainStats("cpu.time=5\n")
	if s.MemoryKnown || s.MemoryLimitKnown {
		t.Errorf("memory reported known without balloon stats: %+v", s)
	}
	s = parseDomainStats(sampleDomStats)
	if !s.MemoryKnown || !s.MemoryLimitKnown {
		t.Errorf("memory not known with balloon stats: %+v", s)
	}
}

func TestLibvirtURIWithSocket(t *testing.T) {
	cases := []struct{ uri, socket, want string }{
		{"", "", "qemu:///system"},
		{"", "/run/alt/libvirt-sock", "qemu+unix:///system?socket=%2Frun%2Falt%2Flibvirt-sock"},
		{"qemu:///session", "/tmp/s", "qemu+unix:///session?socket=%2Ftmp%2Fs"},
		{"qemu+unix:///system?socket=/a", "/b", "qemu+unix:///system?socket=/a"}, // explicit URI wins
		{"qemu+ssh://host/system", "/b", "qemu+ssh://host/system"},               // not a local socket
	}
	for _, c := range cases {
		if got := libvirtURI(c.uri, c.socket); got != c.want {
			t.Errorf("libvirtURI(%q, %q) = %q, want %q", c.uri, c.socket, got, c.want)
		}
	}
}

// The guest agent runs inside the VM, so whatever it says is attacker
// controlled; strings are capped before they become labels.
func TestParseGuestInfo_CapsStrings(t *testing.T) {
	long := strings.Repeat("é", 300) // 600 bytes
	g := parseGuestInfo("hostname : " + long + "\nfs.count : 1\nfs.0.mountpoint : /" + long +
		"\nfs.0.total-bytes : 10\nfs.0.used-bytes : 5\n")
	if g == nil {
		t.Fatal("nil report")
	}
	if len(g.Hostname) > maxGuestString || !utf8.ValidString(g.Hostname) {
		t.Errorf("hostname not capped safely: %d bytes", len(g.Hostname))
	}
	if len(g.Filesystems) != 1 || len(g.Filesystems[0].Mountpoint) > maxGuestString || !utf8.ValidString(g.Filesystems[0].Mountpoint) {
		t.Errorf("mountpoint not capped safely: %+v", g.Filesystems)
	}
}

// Per-domain state is dropped once the domain is gone.
func TestLibvirtPrunesVanishedDomains(t *testing.T) {
	l := NewLibvirtClient(config.VMConfig{}, quietLogger())
	l.prev["a"] = cpuObservation{}
	l.prev["gone"] = cpuObservation{}
	l.guest["a"] = guestCacheEntry{}
	l.guest["gone"] = guestCacheEntry{}
	l.prune(map[string]struct{}{"a": {}})
	if _, ok := l.prev["gone"]; ok {
		t.Error("prev kept a vanished domain")
	}
	if _, ok := l.guest["gone"]; ok {
		t.Error("guest cache kept a vanished domain")
	}
	if _, ok := l.prev["a"]; !ok {
		t.Error("prev dropped a live domain")
	}
}
