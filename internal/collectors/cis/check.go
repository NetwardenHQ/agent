// Package cis implements CIS Benchmark evaluation against a profile the
// operator defines in the Netwarden UI.
//
// # Trust model
//
// The catalog of checks is COMPILED INTO THE AGENT. The server selects which
// checks run, by id, and may override the expected value — it never supplies a
// file path, sysctl key, command, or regex. That asymmetry is the whole
// security design: a compromised control plane can turn checks on and off and
// make them report wrongly, but it cannot make an agent read an arbitrary file
// or execute an arbitrary command on a customer host.
//
// Every probe target in this package is therefore a constant in catalog.go,
// never a value that arrived over the wire. Preserve that property. If a
// future check seems to need a server-supplied path, it needs a new ProbeKind
// with a compiled-in target set instead.
//
// # Layout
//
//	check.go    types, registry, comparison operators
//	profile.go  the server-supplied profile and how it selects checks
//	probes.go   host inspection primitives (Linux)
//	catalog.go  the CIS RHEL check table
//	collector.go the metrics.Collector / SnapshotProvider implementation
package cis

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Status is the outcome of evaluating one check.
type Status string

const (
	// StatusPass means the host matches the expected state.
	StatusPass Status = "pass"

	// StatusFail means the host was inspected successfully and does not match.
	StatusFail Status = "fail"

	// StatusError means the check could not be evaluated — a file the probe
	// needs is unreadable, a required tool is missing. Deliberately distinct
	// from fail: "we could not tell" must never render as "you are compliant",
	// and must not render as a violation either.
	StatusError Status = "error"

	// StatusNotApplicable means the check does not apply to this host — an
	// rpm check on a Debian box, a firewalld check where firewalld isn't the
	// active backend.
	StatusNotApplicable Status = "not_applicable"

	// StatusWaived means the operator waived the check in the profile. The
	// agent still evaluates it (so the UI can show what the state would have
	// been) but marks the result as waived so it does not raise a finding.
	StatusWaived Status = "waived"
)

// Op is the comparison applied between the probe's observed value and the
// check's expected value.
type Op string

const (
	// OpEquals — observed == expected, case-insensitive, whitespace-trimmed.
	OpEquals Op = "eq"

	// OpNotEquals — observed != expected.
	OpNotEquals Op = "ne"

	// OpContains — observed contains expected as a substring.
	OpContains Op = "contains"

	// OpNotContains — observed does not contain expected.
	OpNotContains Op = "not_contains"

	// OpModeAtMost — observed file mode grants no more than expected.
	// "0644" passes when the file is 0644, 0640, or 0600, and fails at 0666.
	// A plain equality test here would produce false failures on hosts that
	// are stricter than the benchmark requires, which trains operators to
	// ignore the list.
	OpModeAtMost Op = "mode_at_most"

	// OpIntAtLeast / OpIntAtMost — numeric bounds, for the many CIS rules
	// phrased as "N or more" / "N or fewer".
	OpIntAtLeast Op = "int_at_least"
	OpIntAtMost  Op = "int_at_most"
)

// ProbeKind identifies which compiled-in inspection primitive a check uses.
// Adding a kind is an agent release; that is intentional (see package doc).
type ProbeKind string

const (
	ProbeSysctl           ProbeKind = "sysctl"
	ProbeKernelModule     ProbeKind = "kernel_module"
	ProbeServiceEnabled   ProbeKind = "service_enabled"
	ProbePackageInstalled ProbeKind = "package_installed"
	ProbeFileMode         ProbeKind = "file_mode"
	ProbeFileOwner        ProbeKind = "file_owner"
	ProbeFileExists       ProbeKind = "file_exists"
	ProbeFileRegex        ProbeKind = "file_regex"
	ProbeSSHDDirective    ProbeKind = "sshd_directive"
	ProbeMountOption      ProbeKind = "mount_option"
	ProbeSELinuxMode      ProbeKind = "selinux_mode"
	ProbeSELinuxPolicy    ProbeKind = "selinux_policy"
	ProbeFirewalldState   ProbeKind = "firewalld_state"
	ProbeAuditRule        ProbeKind = "audit_rule"
	ProbeSysctlPersisted  ProbeKind = "sysctl_persisted"

	// ProbeExtraUIDZero exists because Go's RE2 regexp engine has no negative
	// lookahead, so "a UID 0 line whose name is not root" cannot be written
	// as a ProbeFileRegex pattern. Returns "none" or a comma-separated list
	// of the offending account names.
	ProbeExtraUIDZero ProbeKind = "extra_uid_zero"

	// ProbeSeparatePartition reports whether a path is its own mount point.
	// CIS treats "is a separate partition" as a distinct rule from the mount
	// options on it, because the options are unenforceable without it.
	ProbeSeparatePartition ProbeKind = "separate_partition"

	// ProbeCryptoPolicy reads the system-wide crypto policy (RHEL 8+).
	ProbeCryptoPolicy ProbeKind = "crypto_policy"
)

// Probe describes what to inspect. Every field is populated from the compiled
// catalog — none of it is ever read from the server-supplied profile.
type Probe struct {
	Kind ProbeKind

	// Target is the primary subject: a sysctl key, an absolute file path, a
	// module name, a unit name, a package name, a mount point.
	Target string

	// Arg is a secondary parameter whose meaning depends on Kind: the regex
	// for ProbeFileRegex, the option name for ProbeMountOption, the directive
	// name for ProbeSSHDDirective.
	Arg string
}

// Check is one CIS rule. Checks are values in a compiled table (catalog.go),
// not hand-written functions, so several hundred of them stay reviewable.
type Check struct {
	// ID is the stable identifier the server uses to enable this check and
	// the key findings are deduplicated on. Never renumber a shipped ID:
	// profiles reference it and history is keyed on it.
	ID string

	// Section is the CIS benchmark section, e.g. "3.3.1".
	Section string

	// Title is the benchmark's own rule title.
	Title string

	// Level is the CIS profile level, 1 or 2.
	Level int

	// Probe is what to inspect.
	Probe Probe

	// Op and Expected define the pass condition.
	Op       Op
	Expected string

	// Rationale is a short why, surfaced in the UI next to a failure. Kept on
	// the check rather than server-side so it cannot drift from the logic.
	Rationale string
}

// Result is one evaluated check, as reported to the platform.
//
// Deliberately carries no section/title/level: that metadata is static and
// travels once per report in CatalogEntry, not repeated on every one of a few
// hundred results. The platform joins the two on ID.
type Result struct {
	ID       string `json:"id"`
	Status   Status `json:"status"`
	Expected string `json:"expected,omitempty"`
	Observed string `json:"observed,omitempty"`

	// Detail carries the reason a check errored, or extra context on a
	// failure. Never contains file contents beyond the matched value — a CIS
	// report travels to the platform and must not become an exfiltration path
	// for the files it inspects.
	Detail string `json:"detail,omitempty"`
}

// CatalogEntry is the static description of a check, reported so the platform
// knows what this agent build can actually run.
//
// The profile editor in the UI needs to list selectable checks, and the
// catalog is compiled into the agent — so the agent is the only source of
// truth for it. Reporting it with each result set keeps the UI correct across
// mixed-version fleets and is self-healing: an agent upgrade that adds checks
// makes them selectable without any separate sync step.
type CatalogEntry struct {
	ID        string `json:"id"`
	Section   string `json:"section"`
	Title     string `json:"title"`
	Level     int    `json:"level"`
	Rationale string `json:"rationale"`
}

// CatalogEntries returns the compiled catalog in report form.
func CatalogEntries() []CatalogEntry {
	cat := Catalog()
	out := make([]CatalogEntry, 0, len(cat))
	for _, c := range cat {
		out = append(out, CatalogEntry{
			ID:        c.ID,
			Section:   c.Section,
			Title:     c.Title,
			Level:     c.Level,
			Rationale: c.Rationale,
		})
	}
	return out
}

// -----------------------------------------------------------------------------
// REGISTRY
// -----------------------------------------------------------------------------

var (
	registryMu sync.RWMutex
	registry   = map[string]Check{}
)

// register adds checks to the compiled catalog. Called from catalog.go's init.
// Panics on a duplicate id: two checks sharing an id is a build-time authoring
// mistake that would otherwise silently shadow one of them.
func register(checks ...Check) {
	registryMu.Lock()
	defer registryMu.Unlock()

	for _, c := range checks {
		if c.ID == "" {
			panic("cis: check with empty ID")
		}
		if _, dup := registry[c.ID]; dup {
			panic(fmt.Sprintf("cis: duplicate check ID %q", c.ID))
		}
		if c.Level != 1 && c.Level != 2 {
			panic(fmt.Sprintf("cis: check %q has invalid level %d", c.ID, c.Level))
		}
		registry[c.ID] = c
	}
}

// Lookup returns the compiled check with the given id.
func Lookup(id string) (Check, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	c, ok := registry[id]
	return c, ok
}

// Catalog returns every compiled check, ordered by section. This is what the
// agent reports to the platform so the UI can offer exactly the checks this
// agent version can actually run — a profile referencing an unknown id would
// otherwise fail silently.
func Catalog() []Check {
	registryMu.RLock()
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	registryMu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Section != out[j].Section {
			return sectionLess(out[i].Section, out[j].Section)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// CatalogSize reports how many checks this agent build carries.
func CatalogSize() int {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return len(registry)
}

// sectionLess orders dotted section numbers numerically rather than
// lexically, so 3.3.10 sorts after 3.3.2 instead of before it.
func sectionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := atoi(as[i])
		bi, berr := atoi(bs[i])
		if aerr || berr {
			if as[i] != bs[i] {
				return as[i] < bs[i]
			}
			continue
		}
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}

func atoi(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, true
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, true
		}
		n = n*10 + int(r-'0')
	}
	return n, false
}

// -----------------------------------------------------------------------------
// EVALUATION
// -----------------------------------------------------------------------------

// Evaluator inspects the host. Implemented by the Linux prober; stubbed
// elsewhere. Kept as an interface so the catalog can be tested against
// fixtures without touching the real filesystem.
type Evaluator interface {
	// Observe returns the observed value for a probe. A probe that cannot be
	// evaluated returns an error; a probe whose subject legitimately does not
	// exist on this host returns errNotApplicable.
	Observe(ctx context.Context, p Probe) (string, error)
}

// Evaluate runs one check against an evaluator and classifies the outcome.
func Evaluate(ctx context.Context, ev Evaluator, c Check, expected string) Result {
	res := Result{
		ID:       c.ID,
		Expected: expected,
	}

	observed, err := ev.Observe(ctx, c.Probe)
	if err != nil {
		if isNotApplicable(err) {
			res.Status = StatusNotApplicable
			res.Detail = err.Error()
			return res
		}
		// Could not determine state. Reported as error, never as pass or
		// fail — a check the agent could not run is not evidence either way.
		res.Status = StatusError
		res.Detail = err.Error()
		return res
	}

	res.Observed = observed
	ok, cmpErr := compare(c.Op, observed, expected)
	if cmpErr != nil {
		res.Status = StatusError
		res.Detail = cmpErr.Error()
		return res
	}
	if ok {
		res.Status = StatusPass
	} else {
		res.Status = StatusFail
	}
	return res
}

// compare applies a check's operator.
func compare(op Op, observed, expected string) (bool, error) {
	o := strings.TrimSpace(observed)
	e := strings.TrimSpace(expected)

	switch op {
	case OpEquals:
		return strings.EqualFold(o, e), nil
	case OpNotEquals:
		return !strings.EqualFold(o, e), nil
	case OpContains:
		return strings.Contains(strings.ToLower(o), strings.ToLower(e)), nil
	case OpNotContains:
		return !strings.Contains(strings.ToLower(o), strings.ToLower(e)), nil
	case OpModeAtMost:
		return modeAtMost(o, e)
	case OpIntAtLeast:
		oi, ei, err := twoInts(o, e)
		if err != nil {
			return false, err
		}
		return oi >= ei, nil
	case OpIntAtMost:
		oi, ei, err := twoInts(o, e)
		if err != nil {
			return false, err
		}
		return oi <= ei, nil
	}
	return false, fmt.Errorf("unknown operator %q", op)
}

// modeAtMost reports whether observed grants no permission bit that expected
// does not. Both are octal strings.
func modeAtMost(observed, expected string) (bool, error) {
	o, err := parseOctal(observed)
	if err != nil {
		return false, fmt.Errorf("observed mode %q: %w", observed, err)
	}
	e, err := parseOctal(expected)
	if err != nil {
		return false, fmt.Errorf("expected mode %q: %w", expected, err)
	}
	// Any bit set in observed but not in expected is an excess permission.
	return o&^e == 0, nil
}

func parseOctal(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty mode")
	}
	var n uint32
	for _, r := range s {
		if r < '0' || r > '7' {
			return 0, fmt.Errorf("not octal")
		}
		n = n*8 + uint32(r-'0')
	}
	return n, nil
}

func twoInts(a, b string) (int, int, error) {
	ai, err := parseInt(a)
	if err != nil {
		return 0, 0, fmt.Errorf("observed %q: %w", a, err)
	}
	bi, err := parseInt(b)
	if err != nil {
		return 0, 0, fmt.Errorf("expected %q: %w", b, err)
	}
	return ai, bi, nil
}

func parseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	neg := false
	if s[0] == '-' {
		neg, s = true, s[1:]
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not an integer")
		}
		n = n*10 + int(r-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}
