//go:build linux

package vm

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/NetwardenHQ/agent/internal/config"
)

// LibvirtClient implements HypervisorClient for libvirt-based hypervisors by
// driving the virsh command line. libvirt's own RPC is CGO-only, and a static
// binary is worth more here than one fewer exec.
type LibvirtClient struct {
	config   config.VMConfig
	logger   *slog.Logger
	uri      string
	detector *HypervisorDetector

	availMu      sync.Mutex
	available    bool
	availChecked time.Time

	// prev is each domain's CPU time at the previous observation, keyed by
	// UUID, from which the next observation derives utilization.
	prevMu sync.Mutex
	prev   map[string]cpuObservation

	// guest caches each domain's guest-agent report, keyed by UUID. Asking
	// the agent costs a second exec per VM and, when no agent runs, a wait
	// for libvirt to give up, so the answer (or its absence) is kept for
	// guestInfoTTL.
	guestMu sync.Mutex
	guest   map[string]guestCacheEntry
}

type guestCacheEntry struct {
	info *GuestInfo // nil when the agent did not answer
	at   time.Time
}

// guestInfoTTL is how long a guest-agent report is reused. What it carries
// (OS, hostname, filesystem usage) changes slowly.
const guestInfoTTL = 5 * time.Minute

// maxGuestFilesystems bounds the per-filesystem series one VM may emit.
const maxGuestFilesystems = 16

// maxGuestString caps each string the guest agent reports (hostname,
// mountpoint, OS facts) before it becomes a label value.
const maxGuestString = 255

// capString truncates s to at most n bytes without splitting a UTF-8
// sequence.
func capString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

type cpuObservation struct {
	cpuTime time.Duration
	at      time.Time
}

// LibvirtDomain is the subset of the domain XML the inventory needs.
type LibvirtDomain struct {
	XMLName xml.Name `xml:"domain"`
	Type    string   `xml:"type,attr"`
	Name    string   `xml:"name"`
	UUID    string   `xml:"uuid"`
	Memory  struct {
		Unit  string `xml:"unit,attr"`
		Value int64  `xml:",chardata"`
	} `xml:"memory"`
	VCPU struct {
		Placement string `xml:"placement,attr"`
		Value     int    `xml:",chardata"`
	} `xml:"vcpu"`
	OS struct {
		Type struct {
			Arch    string `xml:"arch,attr"`
			Machine string `xml:"machine,attr"`
			Value   string `xml:",chardata"`
		} `xml:"type"`
	} `xml:"os"`
}

// NewLibvirtClient creates a new libvirt hypervisor client.
func NewLibvirtClient(config config.VMConfig, logger *slog.Logger) *LibvirtClient {
	return &LibvirtClient{
		config:   config,
		logger:   logger,
		uri:      libvirtURI(config.LibvirtURI, config.LibvirtSocket),
		detector: NewHypervisorDetector(),
		prev:     map[string]cpuObservation{},
		guest:    map[string]guestCacheEntry{},
	}
}

// libvirtURI is the connection URI virsh is given. With none configured it
// is the system KVM instance, where production guests live. libvirt_socket
// points a local URI at a non-default daemon socket through libvirt's
// `socket` URI parameter, which needs the unix transport spelled out
// (qemu:///system becomes qemu+unix:///system?socket=...). A URI that already
// names a socket, or a remote one (a host, or a transport other than unix),
// is left alone: the socket setting cannot apply to it.
func libvirtURI(configured, socket string) string {
	uri := configured
	if uri == "" {
		uri = "qemu:///system"
	}
	if socket == "" {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil || u.Host != "" || u.Query().Get("socket") != "" {
		return uri
	}
	driver, transport, hasTransport := strings.Cut(u.Scheme, "+")
	if hasTransport && transport != "unix" {
		return uri
	}
	u.Scheme = driver + "+unix"
	q := u.Query()
	q.Set("socket", socket)
	u.RawQuery = q.Encode()
	return u.String()
}

// Name returns the hypervisor name based on the URI.
func (l *LibvirtClient) Name() string {
	return l.detector.GetHypervisorType(l.uri)
}

// IsAvailable reports whether virsh can reach the daemon, re-checking at
// most once per availabilityTTL: it is asked on every cycle and the answer
// costs a process.
func (l *LibvirtClient) IsAvailable() bool {
	l.availMu.Lock()
	defer l.availMu.Unlock()
	if time.Since(l.availChecked) < availabilityTTL {
		return l.available
	}
	l.availChecked = time.Now()

	if _, err := exec.LookPath("virsh"); err != nil {
		l.logger.Debug("virsh command not found")
		l.available = false
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := l.execVirsh(ctx, "version"); err != nil {
		l.logger.Debug("virsh connection test failed", "uri", l.uri, "error", err)
		l.available = false
		return false
	}
	l.available = true
	return true
}

// execVirsh runs one virsh command against the configured URI.
func (l *LibvirtClient) execVirsh(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "virsh", append([]string{"-c", l.uri}, args...)...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("virsh %s: %w (stderr: %s)", args[0], err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("virsh %s: %w", args[0], err)
	}
	return output, nil
}

// ListVMs returns every domain, running or not.
//
// Domains are addressed by UUID in every virsh call, never by name: a name is
// whatever whoever defined the domain chose, and one starting with '-' would
// be parsed by virsh as an option. A UUID is hex and dashes, starting with a
// hex digit.
func (l *LibvirtClient) ListVMs(ctx context.Context) ([]VM, error) {
	output, err := l.execVirsh(ctx, "list", "--all", "--uuid")
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	vms := make([]VM, 0, len(lines))
	live := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		uuid := strings.TrimSpace(line)
		if !isDomainUUID(uuid) {
			continue
		}
		live[uuid] = struct{}{}
		vm, err := l.getVMDetails(ctx, uuid)
		if err != nil {
			l.logger.Warn("failed to get VM details", "uuid", uuid, "error", err)
			continue
		}
		vms = append(vms, *vm)
	}
	l.prune(live)

	l.logger.Debug("libvirt: listed VMs", "count", len(vms), "uri", l.uri)
	return vms, nil
}

// isDomainUUID reports whether s looks like a libvirt domain UUID: hex digits
// and dashes, starting with a hex digit. Anything else is not passed to virsh.
func isDomainUUID(s string) bool {
	if len(s) < 32 || len(s) > 36 {
		return false
	}
	for i, r := range s {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex && (r != '-' || i == 0) {
			return false
		}
	}
	return true
}

// prune drops the CPU observations and guest-agent reports of deleted
// domains, so neither map grows with every guest ever created on the host.
func (l *LibvirtClient) prune(live map[string]struct{}) {
	l.prevMu.Lock()
	for k := range l.prev {
		if _, ok := live[k]; !ok {
			delete(l.prev, k)
		}
	}
	l.prevMu.Unlock()

	l.guestMu.Lock()
	for k := range l.guest {
		if _, ok := live[k]; !ok {
			delete(l.guest, k)
		}
	}
	l.guestMu.Unlock()
}

// getVMDetails builds the inventory entry for one domain from dominfo and
// its XML definition.
func (l *LibvirtClient) getVMDetails(ctx context.Context, uuid string) (*VM, error) {
	infoOutput, err := l.execVirsh(ctx, "dominfo", uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain info: %w", err)
	}
	xmlOutput, err := l.execVirsh(ctx, "dumpxml", uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain XML: %w", err)
	}

	info := parseKeyValueLines(string(infoOutput), ":")
	name := info["Name"]
	if name == "" {
		return nil, fmt.Errorf("dominfo reported no name")
	}

	var domainXML LibvirtDomain
	if err := xml.Unmarshal(xmlOutput, &domainXML); err != nil {
		l.logger.Warn("failed to parse domain XML", "vm", name, "error", err)
		// The basic facts from dominfo are still worth reporting.
	}

	vm := &VM{
		ID:         uuid,
		Name:       name,
		Hypervisor: l.Name(),
		Status:     normalizeLibvirtStatus(info["State"]),
		OSType:     domainXML.OS.Type.Value,
		CPUCount:   domainXML.VCPU.Value,
		MemoryMB:   memoryMB(domainXML.Memory.Value, domainXML.Memory.Unit),
		Labels: map[string]string{
			"hypervisor_type": domainXML.Type,
			"arch":            domainXML.OS.Type.Arch,
		},
	}
	if domainXML.UUID != "" {
		vm.Labels["uuid"] = domainXML.UUID
	}
	return vm, nil
}

// parseKeyValueLines reads "Key<sep> value" lines into a map.
func parseKeyValueLines(output, sep string) map[string]string {
	info := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, sep)
		if !ok {
			continue
		}
		info[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return info
}

// memoryMB converts a libvirt memory value in the given unit to MiB. libvirt
// defaults to KiB when no unit is given.
func memoryMB(value int64, unit string) int64 {
	switch strings.ToLower(unit) {
	case "bytes", "b":
		return value / (1024 * 1024)
	case "mb", "mib":
		return value
	case "gb", "gib":
		return value * 1024
	default: // "kb", "kib", ""
		return value / 1024
	}
}

// normalizeLibvirtStatus maps virsh's state strings onto the collector's.
func normalizeLibvirtStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	switch {
	case strings.Contains(status, "running"):
		return "running"
	case strings.Contains(status, "shut off"), strings.Contains(status, "shutoff"):
		return "stopped"
	case strings.Contains(status, "paused"), strings.Contains(status, "suspended"):
		return "paused"
	default:
		return status
	}
}

// GetVMStats reads one domain's counters with `virsh domstats`, and the
// guest agent's report when one answers.
func (l *LibvirtClient) GetVMStats(ctx context.Context, vm VM) (*VMStats, error) {
	if !isDomainUUID(vm.ID) {
		return nil, fmt.Errorf("VM %q has no domain UUID", vm.Name)
	}
	output, err := l.execVirsh(ctx, "domstats", vm.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain stats: %w", err)
	}
	stats := parseDomainStats(string(output))
	stats.VMID = vm.ID

	// Utilization is the CPU time consumed since the previous observation,
	// spread over the VM's vCPUs, so 100 means every vCPU was busy.
	vcpus := stats.VCPUCurrent
	if vcpus <= 0 {
		vcpus = vm.CPUCount
	}
	if percent, ok := l.cpuPercent(vm.ID, vcpus, stats.CPUTime, time.Now()); ok {
		stats.CPUUsagePercent, stats.CPUUsageKnown = percent, true
	}

	stats.Guest = l.guestInfo(ctx, vm.ID)
	return stats, nil
}

// cpuPercent derives utilization from two observations of the same domain.
// The first observation, or one whose counter went backwards (the domain was
// restarted), yields no value.
func (l *LibvirtClient) cpuPercent(name string, vcpus int, cpuTimeNs int64, now time.Time) (float64, bool) {
	l.prevMu.Lock()
	defer l.prevMu.Unlock()

	cur := cpuObservation{cpuTime: time.Duration(cpuTimeNs), at: now}
	prev, seen := l.prev[name]
	l.prev[name] = cur

	if !seen || cur.cpuTime < prev.cpuTime {
		return 0, false
	}
	elapsed := now.Sub(prev.at)
	if elapsed <= 0 {
		return 0, false
	}
	if vcpus <= 0 {
		vcpus = 1
	}
	return float64(cur.cpuTime-prev.cpuTime) / float64(elapsed) / float64(vcpus) * 100, true
}

// parseDomainStats reads `virsh domstats` output: `key=value` lines grouped
// by prefix. Groups libvirt added over the years are all optional and set
// their Known flag only when the keys are actually present, so the same
// parser serves libvirt 1.2 (state, cpu, balloon, vcpu, net, block) through
// current releases (rss, guest balloon statistics, disk allocation,
// timings, vcpu wait/delay, dirty rate).
//
// Units as libvirt reports them: cpu.* and vcpu.*.time/wait/delay and
// block.*.times in nanoseconds; balloon.* in KiB; block bytes/allocation/
// capacity/physical in bytes; dirtyrate in MiB/s.
func parseDomainStats(output string) *VMStats {
	stats := &VMStats{}
	var (
		rssKB, currentKB, maximumKB     int64
		unusedKB, availableKB, usableKB int64
		haveUnused, haveUsable          bool
		dirtyStatus                     float64
		dirtyRate                       float64
		haveDirtyRate                   bool
	)

	for _, line := range strings.Split(output, "\n") {
		key, valueStr, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value, err := strconv.ParseFloat(strings.TrimSpace(valueStr), 64)
		if err != nil {
			continue // names, paths and other non-numeric fields
		}
		n := int64(value)

		parts := strings.Split(key, ".")
		group := parts[0]
		// Per-device keys are group.<index>.<field>; the field is what the
		// switches below match on.
		field := ""
		if len(parts) >= 3 {
			field = strings.Join(parts[2:], ".")
		}

		switch group {
		case "cpu":
			switch key {
			case "cpu.time":
				stats.CPUTime = n
			case "cpu.user":
				stats.CPUUserTime, stats.CPUSplitKnown = n, true
			case "cpu.system":
				stats.CPUSystemTime, stats.CPUSplitKnown = n, true
			}

		case "vcpu":
			switch {
			case key == "vcpu.current":
				stats.VCPUCurrent = int(n)
			case key == "vcpu.maximum":
				stats.VCPUMaximum = int(n)
			case field == "wait":
				stats.VCPUWaitTime, stats.VCPUWaitKnown = stats.VCPUWaitTime+n, true
			case field == "delay":
				stats.VCPUDelayTime, stats.VCPUDelayKnown = stats.VCPUDelayTime+n, true
			}

		case "balloon":
			switch key {
			case "balloon.rss":
				rssKB = n
			case "balloon.current":
				currentKB = n
			case "balloon.maximum":
				maximumKB = n
			case "balloon.unused":
				unusedKB, haveUnused = n, true
			case "balloon.available":
				availableKB = n
			case "balloon.usable":
				usableKB, haveUsable = n, true
			case "balloon.swap_in":
				stats.SwapInKB, stats.MemoryFaultsKnown = n, true
			case "balloon.swap_out":
				stats.SwapOutKB, stats.MemoryFaultsKnown = n, true
			case "balloon.major_fault":
				stats.MajorFaults, stats.MemoryFaultsKnown = n, true
			case "balloon.minor_fault":
				stats.MinorFaults, stats.MemoryFaultsKnown = n, true
			}

		case "block":
			switch field {
			case "rd.reqs":
				stats.DiskReadOps += n
			case "rd.bytes":
				stats.DiskReadBytes += n
			case "wr.reqs":
				stats.DiskWriteOps += n
			case "wr.bytes":
				stats.DiskWriteBytes += n
			case "fl.reqs":
				stats.DiskFlushOps += n
			case "rd.times":
				stats.DiskReadTime, stats.DiskTimingKnown = stats.DiskReadTime+n, true
			case "wr.times":
				stats.DiskWriteTime, stats.DiskTimingKnown = stats.DiskWriteTime+n, true
			case "fl.times":
				stats.DiskFlushTime, stats.DiskTimingKnown = stats.DiskFlushTime+n, true
			case "allocation":
				stats.DiskAllocationBytes, stats.DiskAllocationKnown = stats.DiskAllocationBytes+n, true
			case "capacity":
				stats.DiskCapacityBytes, stats.DiskAllocationKnown = stats.DiskCapacityBytes+n, true
			case "physical":
				stats.DiskPhysicalBytes += n
			default:
				if key == "block.count" {
					stats.DiskCount = int(n)
				}
			}

		case "net":
			switch field {
			case "rx.bytes":
				stats.NetworkRxBytes += n
			case "rx.pkts":
				stats.NetworkRxPackets += n
			case "tx.bytes":
				stats.NetworkTxBytes += n
			case "tx.pkts":
				stats.NetworkTxPackets += n
			case "rx.errs":
				stats.NetworkRxErrors, stats.NetworkErrorsKnown = stats.NetworkRxErrors+n, true
			case "tx.errs":
				stats.NetworkTxErrors, stats.NetworkErrorsKnown = stats.NetworkTxErrors+n, true
			case "rx.drop":
				stats.NetworkRxDropped, stats.NetworkErrorsKnown = stats.NetworkRxDropped+n, true
			case "tx.drop":
				stats.NetworkTxDropped, stats.NetworkErrorsKnown = stats.NetworkTxDropped+n, true
			}

		case "dirtyrate":
			switch key {
			case "dirtyrate.calc_status":
				dirtyStatus = value
			case "dirtyrate.megabytes_per_second":
				dirtyRate, haveDirtyRate = value, true
			}
		}
	}

	// Host view: RSS is what the guest occupies; the balloon target stands
	// in for it on hypervisors that do not report RSS.
	// Neither present (no balloon device) means no figure at all.
	usedKB := rssKB
	if usedKB == 0 {
		usedKB = currentKB
	}
	if usedKB > 0 {
		stats.MemoryUsageMB, stats.MemoryKnown = usedKB/1024, true
		if maximumKB > 0 {
			if maximumKB > usedKB {
				stats.MemoryAvailableMB = (maximumKB - usedKB) / 1024
			}
			stats.MemoryUsagePercent = float64(usedKB) / float64(maximumKB) * 100
			stats.MemoryLimitKnown = true
		}
	}

	// Guest view, from the balloon driver's statistics. `available` is the
	// guest's total; `usable` (newer drivers) is what it could reclaim
	// without swapping, `unused` (older) merely what is free right now.
	if availableKB > 0 && (haveUsable || haveUnused) {
		free := unusedKB
		if haveUsable {
			free = usableKB
		}
		if free > availableKB {
			free = availableKB
		}
		stats.GuestMemoryTotalMB = availableKB / 1024
		stats.GuestMemoryUsedMB = (availableKB - free) / 1024
		stats.GuestMemoryUsagePercent = float64(availableKB-free) / float64(availableKB) * 100
		stats.GuestMemoryKnown = true
	}

	// A dirty-rate figure is only a measurement once a calculation has
	// completed (calc_status 2); before that the key may exist with a
	// meaningless value.
	if haveDirtyRate && dirtyStatus == 2 {
		stats.DirtyRateMBps, stats.DirtyRateKnown = dirtyRate, true
	}
	return stats
}

// guestInfo returns the guest agent's report for a domain, from cache when
// fresh. A domain without a responding agent, or a libvirt older than 5.7
// (no `guestinfo` command), yields nil. That answer is cached too, so the
// agent timeout is not paid on every cycle.
func (l *LibvirtClient) guestInfo(ctx context.Context, uuid string) *GuestInfo {
	l.guestMu.Lock()
	entry, ok := l.guest[uuid]
	l.guestMu.Unlock()
	if ok && time.Since(entry.at) < guestInfoTTL {
		return entry.info
	}

	var info *GuestInfo
	output, err := l.execVirsh(ctx, "guestinfo", uuid)
	if err != nil {
		l.logger.Debug("libvirt: no guest agent report", "uuid", uuid, "error", err)
	} else {
		info = parseGuestInfo(string(output))
	}

	l.guestMu.Lock()
	l.guest[uuid] = guestCacheEntry{info: info, at: time.Now()}
	l.guestMu.Unlock()
	return info
}

// parseGuestInfo reads `virsh guestinfo` output: `key : value` lines. Only
// the groups present are filled; an agent that implements none of the
// queries produces an empty report, returned as nil.
func parseGuestInfo(output string) *GuestInfo {
	kv := parseKeyValueLines(output, ":")
	if len(kv) == 0 {
		return nil
	}
	// Everything here comes from inside the guest and becomes a label, so
	// every string is capped.
	str := func(key string) string { return capString(kv[key], maxGuestString) }
	info := &GuestInfo{
		Hostname:      str("hostname"),
		OSName:        str("os.pretty-name"),
		OSVersion:     str("os.version-id"),
		OSID:          str("os.id"),
		KernelRelease: str("os.kernel-release"),
		Arch:          str("os.machine"),
		Timezone:      str("timezone.name"),
	}
	if info.OSName == "" {
		info.OSName = str("os.name")
	}
	if info.OSVersion == "" {
		info.OSVersion = str("os.version")
	}
	if n, err := strconv.Atoi(kv["user.count"]); err == nil {
		info.Users, info.UsersKnown = n, true
	}
	if l1, err := strconv.ParseFloat(kv["load.1m"], 64); err == nil {
		info.Load1 = l1
		info.Load5, _ = strconv.ParseFloat(kv["load.5m"], 64)
		info.Load15, _ = strconv.ParseFloat(kv["load.15m"], 64)
		info.LoadKnown = true
	}

	if count, err := strconv.Atoi(kv["fs.count"]); err == nil {
		for i := 0; i < count && i < maxGuestFilesystems; i++ {
			prefix := "fs." + strconv.Itoa(i) + "."
			total, err := strconv.ParseInt(kv[prefix+"total-bytes"], 10, 64)
			if err != nil || total <= 0 {
				continue // a filesystem the agent could not size (e.g. a pseudo mount)
			}
			used, _ := strconv.ParseInt(kv[prefix+"used-bytes"], 10, 64)
			info.Filesystems = append(info.Filesystems, GuestFilesystem{
				Name:       str(prefix + "name"),
				Mountpoint: str(prefix + "mountpoint"),
				FSType:     str(prefix + "fstype"),
				TotalBytes: total,
				UsedBytes:  used,
			})
		}
	}

	if info.Hostname == "" && info.OSName == "" && !info.UsersKnown && !info.LoadKnown && len(info.Filesystems) == 0 {
		return nil
	}
	return info
}

// Close is a no-op: virsh holds no persistent connection.
func (l *LibvirtClient) Close() error {
	return nil
}
