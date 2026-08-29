//go:build linux

package cis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// notApplicableError marks a probe whose subject legitimately does not exist
// on this host, as distinct from a probe that failed.
type notApplicableError struct{ reason string }

func (e notApplicableError) Error() string { return e.reason }

func notApplicable(format string, args ...any) error {
	return notApplicableError{reason: fmt.Sprintf(format, args...)}
}

func isNotApplicable(err error) bool {
	var na notApplicableError
	return errors.As(err, &na)
}

// LinuxProber inspects the local host. One instance is created per evaluation
// run so its caches stay coherent: a run reads /proc/mounts, the loaded module
// list and the rpm database once each rather than several hundred times.
type LinuxProber struct {
	mu sync.Mutex

	loadedModules map[string]bool
	modulesErr    error
	modulesOnce   sync.Once

	mounts     map[string][]string // mount point -> options
	mountsErr  error
	mountsOnce sync.Once

	installedPkgs map[string]bool
	pkgsErr       error
	pkgsOnce      sync.Once

	sshdDirectives map[string]string
	sshdErr        error
	sshdOnce       sync.Once

	auditRules    string
	auditRulesErr error
	auditOnce     sync.Once

	fileCache map[string]string
}

// NewLinuxProber creates a prober for a single evaluation run.
func NewLinuxProber() *LinuxProber {
	return &LinuxProber{fileCache: map[string]string{}}
}

// Observe dispatches to the primitive for the probe's kind.
func (p *LinuxProber) Observe(ctx context.Context, probe Probe) (string, error) {
	switch probe.Kind {
	case ProbeSysctl:
		return p.sysctl(probe.Target)
	case ProbeSysctlPersisted:
		return p.sysctlPersisted(probe.Target)
	case ProbeKernelModule:
		return p.kernelModuleState(ctx, probe.Target)
	case ProbeServiceEnabled:
		return p.serviceEnabled(ctx, probe.Target)
	case ProbePackageInstalled:
		return p.packageInstalled(ctx, probe.Target)
	case ProbeFileMode:
		return p.fileMode(probe.Target)
	case ProbeFileOwner:
		return p.fileOwner(probe.Target)
	case ProbeFileExists:
		return p.fileExists(probe.Target)
	case ProbeFileRegex:
		return p.fileRegex(probe.Target, probe.Arg)
	case ProbeSSHDDirective:
		return p.sshdDirective(probe.Target)
	case ProbeMountOption:
		return p.mountOption(probe.Target, probe.Arg)
	case ProbeSELinuxMode:
		return p.selinuxMode()
	case ProbeSELinuxPolicy:
		return p.selinuxPolicy()
	case ProbeFirewalldState:
		return p.firewalldState(ctx)
	case ProbeAuditRule:
		return p.auditRule(ctx, probe.Target)
	case ProbeExtraUIDZero:
		return p.extraUIDZero()
	case ProbeSeparatePartition:
		return p.separatePartition(probe.Target)
	case ProbeCryptoPolicy:
		return p.cryptoPolicy()
	}
	return "", fmt.Errorf("unsupported probe kind %q", probe.Kind)
}

// -----------------------------------------------------------------------------
// SYSCTL
// -----------------------------------------------------------------------------

// sysctl reads the running kernel value from /proc/sys rather than shelling
// out to sysctl(8): no exec, no PATH dependency, no parsing of localized
// output.
func (p *LinuxProber) sysctl(key string) (string, error) {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// The knob does not exist — typically the subsystem is compiled
			// out (IPv6 knobs on an IPv6-less kernel). Not a violation.
			return "", notApplicable("sysctl %s not present on this kernel", key)
		}
		return "", fmt.Errorf("reading sysctl %s: %w", key, err)
	}
	return strings.Join(strings.Fields(string(data)), " "), nil
}

// sysctlPersisted reports whether a key is set in the on-disk sysctl config,
// which is what survives a reboot. CIS cares about both the running value and
// the persisted one; a host set correctly only at runtime silently regresses
// on the next boot.
func (p *LinuxProber) sysctlPersisted(key string) (string, error) {
	files := []string{"/etc/sysctl.conf"}
	for _, dir := range []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/lib/sysctl.d"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				files = append(files, filepath.Join(dir, e.Name()))
			}
		}
	}

	// Last assignment wins, matching systemd-sysctl's precedence closely
	// enough for an audit signal.
	value := ""
	for _, f := range files {
		content, err := p.readFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			k, v, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(k), "-")) == key {
				value = strings.TrimSpace(v)
			}
		}
	}
	if value == "" {
		return "unset", nil
	}
	return value, nil
}

// -----------------------------------------------------------------------------
// KERNEL MODULES
// -----------------------------------------------------------------------------

// kernelModuleState returns "disabled" when a module is both unloaded and
// prevented from loading, otherwise "loaded" or "loadable".
//
// CIS phrases these rules as "ensure the filesystem is not available", which
// requires both conditions: a module that is blacklisted but currently loaded
// is still a live exposure, and one that is unloaded but loadable comes back
// on the next mount attempt.
func (p *LinuxProber) kernelModuleState(ctx context.Context, module string) (string, error) {
	loaded, err := p.loadedModuleSet()
	if err != nil {
		return "", err
	}
	if loaded[module] {
		return "loaded", nil
	}

	blocked, err := p.moduleBlocked(module)
	if err != nil {
		return "", err
	}
	if blocked {
		return "disabled", nil
	}
	return "loadable", nil
}

func (p *LinuxProber) loadedModuleSet() (map[string]bool, error) {
	p.modulesOnce.Do(func() {
		data, err := os.ReadFile("/proc/modules")
		if err != nil {
			p.modulesErr = fmt.Errorf("reading /proc/modules: %w", err)
			return
		}
		set := map[string]bool{}
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				set[f[0]] = true
			}
		}
		p.loadedModules = set
	})
	return p.loadedModules, p.modulesErr
}

// moduleBlocked reports whether modprobe config prevents the module loading,
// via either `install <mod> /bin/false` (or /bin/true) or `blacklist <mod>`.
func (p *LinuxProber) moduleBlocked(module string) (bool, error) {
	dirs := []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}
	installRe := regexp.MustCompile(`(?m)^\s*install\s+` + regexp.QuoteMeta(module) + `\s+(/bin/false|/bin/true|/usr/bin/false|/usr/bin/true)\b`)
	blacklistRe := regexp.MustCompile(`(?m)^\s*blacklist\s+` + regexp.QuoteMeta(module) + `\s*$`)

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			content, err := p.readFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			if installRe.MatchString(content) || blacklistRe.MatchString(content) {
				return true, nil
			}
		}
	}
	return false, nil
}

// -----------------------------------------------------------------------------
// SERVICES / PACKAGES
// -----------------------------------------------------------------------------

// serviceEnabled reports a unit's enablement state via systemctl. Returns
// "not-found" for units that aren't installed, which most CIS service rules
// treat as satisfied.
func (p *LinuxProber) serviceEnabled(ctx context.Context, unit string) (string, error) {
	out, err := p.run(ctx, "systemctl", "is-enabled", unit)
	out = strings.TrimSpace(out)
	if out != "" {
		// systemctl exits non-zero for disabled/not-found while still
		// printing the state, so the output is authoritative when present.
		return out, nil
	}
	if err != nil {
		return "", fmt.Errorf("systemctl is-enabled %s: %w", unit, err)
	}
	return "unknown", nil
}

// packageInstalled reports "installed" or "absent" using the rpm database.
func (p *LinuxProber) packageInstalled(ctx context.Context, pkg string) (string, error) {
	set, err := p.installedPackageSet(ctx)
	if err != nil {
		return "", err
	}
	if set[pkg] {
		return "installed", nil
	}
	return "absent", nil
}

func (p *LinuxProber) installedPackageSet(ctx context.Context) (map[string]bool, error) {
	p.pkgsOnce.Do(func() {
		out, err := p.run(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\\n")
		if err != nil {
			p.pkgsErr = notApplicable("rpm is not available on this host")
			return
		}
		set := map[string]bool{}
		for _, line := range strings.Split(out, "\n") {
			if name := strings.TrimSpace(line); name != "" {
				set[name] = true
			}
		}
		p.installedPkgs = set
	})
	return p.installedPkgs, p.pkgsErr
}

// -----------------------------------------------------------------------------
// FILES
// -----------------------------------------------------------------------------

func (p *LinuxProber) fileMode(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", notApplicable("%s does not exist", path)
		}
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	return fmt.Sprintf("%04o", info.Mode().Perm()), nil
}

func (p *LinuxProber) fileOwner(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", notApplicable("%s does not exist", path)
		}
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("cannot read ownership of %s", path)
	}
	return fmt.Sprintf("%d:%d", st.Uid, st.Gid), nil
}

func (p *LinuxProber) fileExists(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "absent", nil
		}
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	return "present", nil
}

// fileRegex reports "match" or "no-match" for a compiled-in pattern.
//
// Only the match verdict is returned, never the matched text. A CIS report
// travels to the platform, and these probes read files like /etc/shadow and
// sudoers; returning captured content would turn a compliance report into an
// exfiltration path.
func (p *LinuxProber) fileRegex(path, pattern string) (string, error) {
	content, err := p.readFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", notApplicable("%s does not exist", path)
		}
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		// A bad pattern is an authoring bug in catalog.go, not a host problem.
		return "", fmt.Errorf("invalid catalog pattern for %s: %w", path, err)
	}
	if re.MatchString(content) {
		return "match", nil
	}
	return "no-match", nil
}

// readFile reads and caches a file for the lifetime of this run, capped so a
// pathological file cannot balloon agent memory.
func (p *LinuxProber) readFile(path string) (string, error) {
	p.mu.Lock()
	if v, ok := p.fileCache[path]; ok {
		p.mu.Unlock()
		return v, nil
	}
	p.mu.Unlock()

	const maxFileSize = 4 << 20 // 4 MiB
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, maxFileSize)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		if err.Error() == "EOF" {
			return "", nil
		}
		return "", err
	}
	content := string(buf[:n])

	p.mu.Lock()
	p.fileCache[path] = content
	p.mu.Unlock()
	return content, nil
}

// -----------------------------------------------------------------------------
// SSHD
// -----------------------------------------------------------------------------

// sshdDirective returns the effective value of an sshd_config directive, or
// "unset" when absent. First match wins, which is sshd's own precedence.
func (p *LinuxProber) sshdDirective(directive string) (string, error) {
	p.sshdOnce.Do(func() {
		content, err := p.readFile("/etc/ssh/sshd_config")
		if err != nil {
			p.sshdErr = notApplicable("sshd_config not readable")
			return
		}
		parsed := map[string]string{}
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if hash := strings.Index(line, " #"); hash >= 0 {
				line = strings.TrimSpace(line[:hash])
			}
			key, value, found := strings.Cut(line, " ")
			if !found {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			if _, exists := parsed[key]; !exists {
				parsed[key] = strings.TrimSpace(value)
			}
		}
		p.sshdDirectives = parsed
	})
	if p.sshdErr != nil {
		return "", p.sshdErr
	}
	if v, ok := p.sshdDirectives[strings.ToLower(directive)]; ok {
		return v, nil
	}
	return "unset", nil
}

// -----------------------------------------------------------------------------
// MOUNTS
// -----------------------------------------------------------------------------

// mountOption reports "present"/"absent" for an option on a mount point, or
// not-applicable when the path is not a separate mount. CIS treats a missing
// separate partition as its own finding, checked separately.
func (p *LinuxProber) mountOption(mountPoint, option string) (string, error) {
	mounts, err := p.mountTable()
	if err != nil {
		return "", err
	}
	opts, ok := mounts[mountPoint]
	if !ok {
		return "", notApplicable("%s is not a separate mount point", mountPoint)
	}
	for _, o := range opts {
		if o == option {
			return "present", nil
		}
	}
	return "absent", nil
}

func (p *LinuxProber) mountTable() (map[string][]string, error) {
	p.mountsOnce.Do(func() {
		data, err := os.ReadFile("/proc/mounts")
		if err != nil {
			p.mountsErr = fmt.Errorf("reading /proc/mounts: %w", err)
			return
		}
		table := map[string][]string{}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			// /proc/mounts octal-escapes spaces in mount points.
			mp := strings.ReplaceAll(f[1], `\040`, " ")
			table[mp] = strings.Split(f[3], ",")
		}
		p.mounts = table
	})
	return p.mounts, p.mountsErr
}

// -----------------------------------------------------------------------------
// SELINUX / FIREWALL / AUDIT
// -----------------------------------------------------------------------------

// selinuxMode returns enforcing / permissive / disabled.
func (p *LinuxProber) selinuxMode() (string, error) {
	data, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		// No SELinux filesystem: either not built in or fully disabled. On a
		// RHEL host this is a genuine finding, so report it rather than
		// marking the check not-applicable.
		return "disabled", nil
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		return "enforcing", nil
	case "0":
		return "permissive", nil
	}
	return "unknown", nil
}

// selinuxPolicy returns the configured policy type (targeted / mls).
func (p *LinuxProber) selinuxPolicy() (string, error) {
	content, err := p.readFile("/etc/selinux/config")
	if err != nil {
		return "", notApplicable("/etc/selinux/config not present")
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SELINUXTYPE=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "SELINUXTYPE=")), nil
		}
	}
	return "unset", nil
}

// firewalldState reports whether firewalld is running.
func (p *LinuxProber) firewalldState(ctx context.Context) (string, error) {
	out, _ := p.run(ctx, "systemctl", "is-active", "firewalld")
	state := strings.TrimSpace(out)
	if state == "" {
		return "unknown", nil
	}
	return state, nil
}

// auditRule reports whether a rule matching the compiled-in pattern is loaded.
func (p *LinuxProber) auditRule(ctx context.Context, pattern string) (string, error) {
	p.auditOnce.Do(func() {
		out, err := p.run(ctx, "auditctl", "-l")
		if err != nil {
			p.auditRulesErr = notApplicable("auditctl unavailable")
			return
		}
		p.auditRules = out
	})
	if p.auditRulesErr != nil {
		return "", p.auditRulesErr
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid catalog audit pattern: %w", err)
	}
	if re.MatchString(p.auditRules) {
		return "present", nil
	}
	return "absent", nil
}

// extraUIDZero returns "none", or a comma-separated list of non-root accounts
// with UID 0. A dedicated probe because RE2 has no negative lookahead, so
// "UID 0 and not root" is not expressible as a single catalog pattern.
//
// Account names are returned because an operator cannot act on "1 extra
// account" — they need to know which. Names are not secrets in the way the
// password hashes in the same file are.
func (p *LinuxProber) extraUIDZero() (string, error) {
	content, err := p.readFile("/etc/passwd")
	if err != nil {
		return "", fmt.Errorf("reading /etc/passwd: %w", err)
	}

	var offenders []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[2] == "0" && fields[0] != "root" {
			offenders = append(offenders, fields[0])
		}
	}
	if len(offenders) == 0 {
		return "none", nil
	}
	return strings.Join(offenders, ","), nil
}

// separatePartition reports whether a path is its own mount point.
func (p *LinuxProber) separatePartition(path string) (string, error) {
	mounts, err := p.mountTable()
	if err != nil {
		return "", err
	}
	if _, ok := mounts[path]; ok {
		return "separate", nil
	}
	return "shared", nil
}

// cryptoPolicy reads the RHEL system-wide cryptographic policy. LEGACY
// re-enables SHA-1 signatures and 1024-bit DH, so the policy name is itself a
// meaningful posture signal.
func (p *LinuxProber) cryptoPolicy() (string, error) {
	content, err := p.readFile("/etc/crypto-policies/config")
	if err != nil {
		return "", notApplicable("crypto-policies not present on this host")
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line, nil
	}
	return "unset", nil
}

// -----------------------------------------------------------------------------
// COMMAND EXECUTION
// -----------------------------------------------------------------------------

// allowedCommands is the complete set of binaries CIS probes may execute.
// Compiled in, never influenced by the profile. Arguments are likewise always
// constants from catalog.go or this file.
var allowedCommands = map[string]bool{
	"systemctl": true,
	"rpm":       true,
	"auditctl":  true,
}

// run executes an allowlisted command with a bounded timeout and a scrubbed
// environment. Output is capped so a runaway command cannot exhaust memory.
func (p *LinuxProber) run(ctx context.Context, name string, args ...string) (string, error) {
	if !allowedCommands[name] {
		return "", fmt.Errorf("command %q is not allowlisted for CIS probes", name)
	}

	path, err := exec.LookPath(name)
	if err != nil {
		return "", notApplicable("%s is not installed", name)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

	out, err := cmd.Output()
	const maxOutput = 1 << 20 // 1 MiB
	if len(out) > maxOutput {
		out = out[:maxOutput]
	}
	return string(out), err
}
