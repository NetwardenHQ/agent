package cis

import (
	"context"
	"testing"
)

// fakeProber returns canned observations, so evaluation semantics can be
// tested without touching the real host.
type fakeProber struct {
	values map[ProbeKind]string
	err    error
}

func (f fakeProber) Observe(_ context.Context, p Probe) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if v, ok := f.values[p.Kind]; ok {
		return v, nil
	}
	return "", nil
}

func firstCheckID(t *testing.T) string {
	t.Helper()
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("empty catalog")
	}
	return cat[0].ID
}

// -----------------------------------------------------------------------------
// TRUST BOUNDARY
// -----------------------------------------------------------------------------

// The single most important property in this package: a profile arriving from
// the server selects checks and adjusts expected values. It must not be able
// to influence WHAT a check inspects. If this test ever fails, a compromised
// or malicious control plane can read arbitrary files on every customer host.
func TestProfileCannotAlterProbeTargets(t *testing.T) {
	id := "cis_rhel9_7_1_5" // /etc/shadow mode
	original, ok := Lookup(id)
	if !ok {
		t.Fatalf("check %s missing from catalog", id)
	}

	profile := &Profile{
		Revision:      1,
		EnabledChecks: []string{id},
		Overrides: map[string]Override{
			id: {Expected: "0777"},
		},
	}

	plan := profile.Resolve()
	if len(plan.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(plan.Items))
	}
	item := plan.Items[0]

	// The expected value is operator-controlled, by design.
	if item.Expected != "0777" {
		t.Errorf("override not applied: got %q", item.Expected)
	}

	// The probe is not, under any circumstances.
	if item.Check.Probe.Target != original.Probe.Target {
		t.Fatalf("SECURITY: profile altered probe target %q -> %q",
			original.Probe.Target, item.Check.Probe.Target)
	}
	if item.Check.Probe.Kind != original.Probe.Kind {
		t.Fatalf("SECURITY: profile altered probe kind %q -> %q",
			original.Probe.Kind, item.Check.Probe.Kind)
	}
	if item.Check.Probe.Arg != original.Probe.Arg {
		t.Fatalf("SECURITY: profile altered probe arg %q -> %q",
			original.Probe.Arg, item.Check.Probe.Arg)
	}
}

// A profile naming a check this build does not carry must be reported, not
// silently ignored — otherwise an operator sees a check enabled in the UI that
// never produces a result and has no way to find out why.
func TestProfileReportsUnknownChecks(t *testing.T) {
	profile := &Profile{
		Revision:      2,
		EnabledChecks: []string{firstCheckID(t), "cis_rhel9_from_the_future", "totally_made_up"},
	}
	plan := profile.Resolve()

	if len(plan.Items) != 1 {
		t.Errorf("expected 1 runnable item, got %d", len(plan.Items))
	}
	if len(plan.UnknownChecks) != 2 {
		t.Fatalf("expected 2 unknown checks, got %v", plan.UnknownChecks)
	}
}

// -----------------------------------------------------------------------------
// SELECTION
// -----------------------------------------------------------------------------

func TestNilProfileRunsNothing(t *testing.T) {
	var p *Profile
	if plan := p.Resolve(); len(plan.Items) != 0 {
		t.Errorf("nil profile must select no checks, got %d", len(plan.Items))
	}
}

func TestEmptyEnabledChecksMeansAllAtLevel(t *testing.T) {
	plan := (&Profile{Revision: 1, Levels: []int{1}}).Resolve()
	if len(plan.Items) == 0 {
		t.Fatal("expected all Level 1 checks")
	}
	for _, item := range plan.Items {
		if item.Check.Level != 1 {
			t.Errorf("%s: level %d leaked into a Level 1 plan", item.Check.ID, item.Check.Level)
		}
	}

	both := (&Profile{Revision: 1, Levels: []int{1, 2}}).Resolve()
	if len(both.Items) <= len(plan.Items) {
		t.Errorf("L1+L2 (%d) should select more than L1 alone (%d)", len(both.Items), len(plan.Items))
	}
}

func TestLevelFilterAppliesToExplicitChecks(t *testing.T) {
	// Find a Level 2 check and enable it under a Level 1 profile.
	var l2 string
	for _, c := range Catalog() {
		if c.Level == 2 {
			l2 = c.ID
			break
		}
	}
	if l2 == "" {
		t.Skip("no level 2 checks")
	}

	plan := (&Profile{Revision: 1, Levels: []int{1}, EnabledChecks: []string{l2}}).Resolve()
	if len(plan.Items) != 0 {
		t.Errorf("level filter should exclude the L2 check, got %d items", len(plan.Items))
	}
}

func TestDuplicateEnabledChecksRunOnce(t *testing.T) {
	id := firstCheckID(t)
	plan := (&Profile{Revision: 1, EnabledChecks: []string{id, id, id}}).Resolve()
	if len(plan.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(plan.Items))
	}
}

func TestEmptyOverrideDoesNotClobberCatalogExpectation(t *testing.T) {
	id := "cis_rhel9_7_1_5"
	original, _ := Lookup(id)
	plan := (&Profile{
		Revision:      1,
		EnabledChecks: []string{id},
		Overrides:     map[string]Override{id: {Expected: "   "}},
	}).Resolve()

	if plan.Items[0].Expected != original.Expected {
		t.Errorf("blank override replaced the catalog expectation with %q", plan.Items[0].Expected)
	}
}

// -----------------------------------------------------------------------------
// EVALUATION SEMANTICS
// -----------------------------------------------------------------------------

func TestEvaluateStatuses(t *testing.T) {
	check := Check{
		ID: "t1", Section: "1.1", Title: "test", Level: 1,
		Probe: Probe{Kind: ProbeSysctl, Target: "x"},
		Op:    OpEquals, Expected: "0",
	}

	pass := Evaluate(context.Background(), fakeProber{values: map[ProbeKind]string{ProbeSysctl: "0"}}, check, "0")
	if pass.Status != StatusPass {
		t.Errorf("expected pass, got %s", pass.Status)
	}

	fail := Evaluate(context.Background(), fakeProber{values: map[ProbeKind]string{ProbeSysctl: "1"}}, check, "0")
	if fail.Status != StatusFail {
		t.Errorf("expected fail, got %s", fail.Status)
	}
	if fail.Observed != "1" {
		t.Errorf("observed value not recorded: %q", fail.Observed)
	}
}

// A check the agent could not run is not evidence in either direction. It must
// never be reported as pass (hiding a real gap) or fail (a violation that was
// never observed).
func TestUnreadableCheckIsErrorNotFail(t *testing.T) {
	check := Check{
		ID: "t2", Section: "1.1", Title: "test", Level: 1,
		Probe: Probe{Kind: ProbeFileMode, Target: "/nonexistent"},
		Op:    OpModeAtMost, Expected: "0600",
	}
	res := Evaluate(context.Background(), fakeProber{err: errProbeFailed}, check, "0600")
	if res.Status != StatusError {
		t.Fatalf("expected error status, got %s", res.Status)
	}
	if res.Status == StatusPass || res.Status == StatusFail {
		t.Fatal("an unevaluable check must not be scored")
	}
}

func TestOverriddenExpectationIsUsed(t *testing.T) {
	check := Check{
		ID: "t3", Section: "3.3.1", Title: "ip forward", Level: 1,
		Probe: Probe{Kind: ProbeSysctl, Target: "net.ipv4.ip_forward"},
		Op:    OpEquals, Expected: "0",
	}
	ev := fakeProber{values: map[ProbeKind]string{ProbeSysctl: "1"}}

	// A router legitimately forwards; with the catalog default this fails.
	if r := Evaluate(context.Background(), ev, check, "0"); r.Status != StatusFail {
		t.Errorf("expected fail against catalog default, got %s", r.Status)
	}
	// With the operator's override it passes.
	if r := Evaluate(context.Background(), ev, check, "1"); r.Status != StatusPass {
		t.Errorf("expected pass against override, got %s", r.Status)
	}
}

// -----------------------------------------------------------------------------
// OPERATORS
// -----------------------------------------------------------------------------

func TestModeAtMost(t *testing.T) {
	for _, tc := range []struct {
		observed, expected string
		want               bool
	}{
		{"0600", "0644", true},  // stricter than required
		{"0644", "0644", true},  // exact
		{"0640", "0644", true},  // stricter
		{"0666", "0644", false}, // world-writable
		{"0645", "0644", false}, // extra world-execute
		{"0000", "0000", true},
		{"0400", "0000", false}, // any bit over 0000 is excess
		{"0700", "0755", true},
	} {
		got, err := modeAtMost(tc.observed, tc.expected)
		if err != nil {
			t.Fatalf("modeAtMost(%q,%q): %v", tc.observed, tc.expected, err)
		}
		if got != tc.want {
			t.Errorf("modeAtMost(%q,%q) = %v, want %v", tc.observed, tc.expected, got, tc.want)
		}
	}
}

func TestCompareOperators(t *testing.T) {
	cases := []struct {
		op       Op
		obs, exp string
		want     bool
	}{
		{OpEquals, "yes", "YES", true}, // case-insensitive
		{OpEquals, " no ", "no", true}, // trimmed
		{OpNotEquals, "enabled", "enabled", false},
		{OpNotEquals, "disabled", "enabled", true},
		{OpContains, "aes256-gcm,chacha20", "chacha20", true},
		{OpNotContains, "aes256-gcm", "3des", true},
		{OpIntAtLeast, "14", "14", true},
		{OpIntAtLeast, "13", "14", false},
		{OpIntAtMost, "4", "5", true},
		{OpIntAtMost, "6", "5", false},
	}
	for _, tc := range cases {
		got, err := compare(tc.op, tc.obs, tc.exp)
		if err != nil {
			t.Errorf("compare(%s,%q,%q): %v", tc.op, tc.obs, tc.exp, err)
			continue
		}
		if got != tc.want {
			t.Errorf("compare(%s,%q,%q) = %v, want %v", tc.op, tc.obs, tc.exp, got, tc.want)
		}
	}

	if _, err := compare("bogus_op", "a", "b"); err == nil {
		t.Error("unknown operator should error, not silently pass")
	}
}

// -----------------------------------------------------------------------------
// SCORING
// -----------------------------------------------------------------------------

// Errored, waived and not-applicable checks must not move the score. Counting
// an unreadable check as a failure makes the score drop when the agent loses a
// permission, which reads as a compliance regression that never happened.
func TestScoreExcludesNonScorableStatuses(t *testing.T) {
	results := []Result{
		{Status: StatusPass}, {Status: StatusPass}, {Status: StatusPass},
		{Status: StatusFail},
		{Status: StatusError}, {Status: StatusError},
		{Status: StatusNotApplicable},
		{Status: StatusWaived},
	}
	s := Summarize(results)

	if s.Total != 8 {
		t.Errorf("total = %d, want 8", s.Total)
	}
	if s.Pass != 3 || s.Fail != 1 || s.Error != 2 || s.NotApplicable != 1 || s.Waived != 1 {
		t.Errorf("bad tally: %+v", s)
	}
	// 3 pass / 4 scorable = 75%, unaffected by the 4 non-scorable results.
	if got := s.Score(); got != 75 {
		t.Errorf("score = %v, want 75", got)
	}
}

func TestScoreWithNothingScorable(t *testing.T) {
	s := Summarize([]Result{{Status: StatusError}, {Status: StatusNotApplicable}})
	if got := s.Score(); got != 0 {
		t.Errorf("score = %v, want 0 when nothing is scorable", got)
	}
}

var errProbeFailed = &probeError{"permission denied"}

type probeError struct{ msg string }

func (e *probeError) Error() string { return e.msg }
