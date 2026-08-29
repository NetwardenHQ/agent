package cis

import (
	"regexp"
	"strings"
	"testing"
)

// Every ProbeFileRegex / ProbeAuditRule pattern in the catalog must compile
// under RE2. Go's regexp has no lookahead or backreferences, so a pattern
// written from PCRE habit compiles nowhere and turns its check into a
// permanent StatusError that looks like a host problem.
func TestCatalogPatternsCompile(t *testing.T) {
	for _, c := range Catalog() {
		var pattern string
		switch c.Probe.Kind {
		case ProbeFileRegex:
			pattern = c.Probe.Arg
		case ProbeAuditRule:
			pattern = c.Probe.Target
		default:
			continue
		}
		if pattern == "" {
			t.Errorf("%s: %s probe with empty pattern", c.ID, c.Probe.Kind)
			continue
		}
		if _, err := regexp.Compile(pattern); err != nil {
			t.Errorf("%s: pattern does not compile under RE2: %v", c.ID, err)
		}
	}
}

func TestCatalogIsWellFormed(t *testing.T) {
	seenSection := map[string]string{}

	for _, c := range Catalog() {
		if !strings.HasPrefix(c.ID, "cis_rhel9_") {
			t.Errorf("%s: id should be namespaced by benchmark", c.ID)
		}
		if c.Section == "" {
			t.Errorf("%s: missing section", c.ID)
		}
		if c.Title == "" {
			t.Errorf("%s: missing title", c.ID)
		}
		if c.Level != 1 && c.Level != 2 {
			t.Errorf("%s: level %d is not 1 or 2", c.ID, c.Level)
		}
		if c.Probe.Kind == "" {
			t.Errorf("%s: missing probe kind", c.ID)
		}
		if c.Op == "" {
			t.Errorf("%s: missing operator", c.ID)
		}
		// Rationale is shown to a human deciding whether to act. A missing or
		// stub one makes the finding unactionable.
		if len(c.Rationale) < 40 {
			t.Errorf("%s: rationale too short to be useful (%d chars)", c.ID, len(c.Rationale))
		}
		if prev, dup := seenSection[c.Section]; dup {
			t.Errorf("section %s used by both %s and %s", c.Section, prev, c.ID)
		}
		seenSection[c.Section] = c.ID
	}
}

// Probes that need a target must have one, or they silently inspect nothing.
func TestCatalogProbesHaveTargets(t *testing.T) {
	needsTarget := map[ProbeKind]bool{
		ProbeSysctl: true, ProbeSysctlPersisted: true, ProbeKernelModule: true,
		ProbeServiceEnabled: true, ProbePackageInstalled: true, ProbeFileMode: true,
		ProbeFileOwner: true, ProbeFileExists: true, ProbeFileRegex: true,
		ProbeSSHDDirective: true, ProbeMountOption: true, ProbeAuditRule: true,
	}
	needsArg := map[ProbeKind]bool{
		ProbeFileRegex: true, ProbeMountOption: true,
	}

	for _, c := range Catalog() {
		if needsTarget[c.Probe.Kind] && c.Probe.Target == "" {
			t.Errorf("%s: probe kind %s requires a target", c.ID, c.Probe.Kind)
		}
		if needsArg[c.Probe.Kind] && c.Probe.Arg == "" {
			t.Errorf("%s: probe kind %s requires an arg", c.ID, c.Probe.Kind)
		}
	}
}

// File paths in the catalog must be absolute. A relative path would resolve
// against the agent's working directory, which is not a meaningful location
// and would differ between systemd and a manual invocation.
func TestCatalogFilePathsAreAbsolute(t *testing.T) {
	fileProbes := map[ProbeKind]bool{
		ProbeFileMode: true, ProbeFileOwner: true,
		ProbeFileExists: true, ProbeFileRegex: true,
	}
	for _, c := range Catalog() {
		if fileProbes[c.Probe.Kind] && !strings.HasPrefix(c.Probe.Target, "/") {
			t.Errorf("%s: file path %q is not absolute", c.ID, c.Probe.Target)
		}
	}
}

// Mode expectations must be valid octal, or the comparison errors at runtime
// on every host.
func TestCatalogModeExpectationsAreOctal(t *testing.T) {
	for _, c := range Catalog() {
		if c.Op != OpModeAtMost {
			continue
		}
		if _, err := parseOctal(c.Expected); err != nil {
			t.Errorf("%s: expected mode %q is not octal: %v", c.ID, c.Expected, err)
		}
	}
}

func TestCatalogCoversBothLevels(t *testing.T) {
	levels := map[int]int{}
	sections := map[string]int{}
	for _, c := range Catalog() {
		levels[c.Level]++
		sections[strings.SplitN(c.Section, ".", 2)[0]]++
	}
	if levels[1] == 0 {
		t.Error("catalog has no Level 1 checks")
	}
	if levels[2] == 0 {
		t.Error("catalog has no Level 2 checks")
	}
	// The benchmark's seven top-level sections should all be represented;
	// a missing one means a whole domain silently has no coverage.
	for _, section := range []string{"1", "2", "3", "4", "5", "6", "7"} {
		if sections[section] == 0 {
			t.Errorf("no checks for benchmark section %s", section)
		}
	}
	t.Logf("catalog: %d checks (L1=%d L2=%d) across %d sections",
		CatalogSize(), levels[1], levels[2], len(sections))
}

// Sections must sort numerically, not lexically, or 3.3.10 appears before
// 3.3.2 in the UI.
func TestSectionOrdering(t *testing.T) {
	if !sectionLess("3.3.2", "3.3.10") {
		t.Error("3.3.2 should sort before 3.3.10")
	}
	if sectionLess("3.3.10", "3.3.2") {
		t.Error("3.3.10 must not sort before 3.3.2")
	}
	if !sectionLess("1.1.1", "1.1.1.1") {
		t.Error("a shorter prefix should sort first")
	}

	cat := Catalog()
	for i := 1; i < len(cat); i++ {
		if sectionLess(cat[i].Section, cat[i-1].Section) {
			t.Fatalf("catalog not ordered: %s before %s", cat[i-1].Section, cat[i].Section)
		}
	}
}
