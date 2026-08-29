package cis

import (
	"sort"
	"strings"
)

// Profile is the CIS configuration the operator defines in the Netwarden UI,
// delivered to the agent on the existing /agent/config poll.
//
// Note what is NOT here: no paths, no commands, no regexes, no sysctl keys.
// The profile selects from the compiled catalog by id and may adjust expected
// values. Everything about *how* a check inspects the host lives in
// catalog.go. See the package doc for why.
type Profile struct {
	// Revision increments on every save in the UI. The agent logs when it
	// picks up a new one, which is what makes "why is this host still failing
	// a check I just waived" answerable.
	Revision int `json:"revision"`

	// Benchmark identifies the CIS benchmark the profile targets, e.g.
	// "cis-rhel9". Advisory: the agent reports it back on results so the
	// platform can flag a profile aimed at a different OS than the host runs.
	Benchmark string `json:"benchmark"`

	// Levels selects CIS profile levels to run, e.g. [1] or [1,2]. Applied as
	// a filter on top of EnabledChecks.
	Levels []int `json:"levels"`

	// EnabledChecks lists check ids to run. Empty means "every catalog check
	// matching Levels", which is what a freshly created profile does.
	EnabledChecks []string `json:"enabled_checks"`

	// Overrides adjusts the expected value for specific checks. Keyed by
	// check id. Only the expected value can be overridden — never the probe.
	Overrides map[string]Override `json:"overrides"`

	// Waivers lists check ids the operator has accepted the risk on. Waived
	// checks are still evaluated and reported, marked StatusWaived, so the UI
	// can show the real state without raising a finding. Silently skipping
	// them would make a waiver indistinguishable from a broken check.
	Waivers []string `json:"waivers"`
}

// Override adjusts a single check's pass condition.
type Override struct {
	// Expected replaces the catalog's expected value. The operator is
	// deliberately allowed to do this — plenty of CIS defaults are wrong for
	// a given estate (a router legitimately sets net.ipv4.ip_forward=1).
	Expected string `json:"expected"`
}

// Plan is a resolved profile: the concrete list of checks to run this cycle,
// with expected values and waiver status already applied.
type Plan struct {
	Revision  int
	Benchmark string
	Levels    []int
	Items     []PlanItem

	// UnknownChecks are ids the profile enabled that this agent build does
	// not carry. Reported back so the UI can tell the operator their profile
	// references checks needing an agent upgrade, rather than those checks
	// just never appearing in results.
	UnknownChecks []string
}

// PlanItem is one check to run, with the profile applied.
type PlanItem struct {
	Check    Check
	Expected string
	Waived   bool
}

// Resolve turns a profile into a concrete plan against the compiled catalog.
//
// A nil profile yields an empty plan: with no profile defined in the UI, the
// agent runs nothing. CIS evaluation reads a lot of system state, and doing
// that on hosts whose operator never asked for it is not a default worth
// having.
func (p *Profile) Resolve() Plan {
	if p == nil {
		return Plan{}
	}

	plan := Plan{Revision: p.Revision, Benchmark: p.Benchmark, Levels: p.Levels}

	levels := map[int]bool{}
	for _, l := range p.Levels {
		levels[l] = true
	}
	// No levels named means no level filter rather than "no checks" — a
	// profile that enabled checks explicitly but forgot Levels should still
	// run them.
	levelAllowed := func(l int) bool {
		if len(levels) == 0 {
			return true
		}
		return levels[l]
	}

	waived := map[string]bool{}
	for _, id := range p.Waivers {
		waived[id] = true
	}

	var selected []Check
	if len(p.EnabledChecks) == 0 {
		for _, c := range Catalog() {
			if levelAllowed(c.Level) {
				selected = append(selected, c)
			}
		}
	} else {
		seen := map[string]bool{}
		for _, id := range p.EnabledChecks {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true

			c, ok := Lookup(id)
			if !ok {
				plan.UnknownChecks = append(plan.UnknownChecks, id)
				continue
			}
			if !levelAllowed(c.Level) {
				continue
			}
			selected = append(selected, c)
		}
	}

	for _, c := range selected {
		expected := c.Expected
		if ov, ok := p.Overrides[c.ID]; ok && strings.TrimSpace(ov.Expected) != "" {
			expected = ov.Expected
		}
		plan.Items = append(plan.Items, PlanItem{
			Check:    c,
			Expected: expected,
			Waived:   waived[c.ID],
		})
	}

	sort.Slice(plan.Items, func(i, j int) bool {
		if plan.Items[i].Check.Section != plan.Items[j].Check.Section {
			return sectionLess(plan.Items[i].Check.Section, plan.Items[j].Check.Section)
		}
		return plan.Items[i].Check.ID < plan.Items[j].Check.ID
	})
	sort.Strings(plan.UnknownChecks)

	return plan
}

// Summary counts results by status, for the scalar gauges the agent emits
// alongside the detailed snapshot.
type Summary struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Error         int `json:"error"`
	NotApplicable int `json:"not_applicable"`
	Waived        int `json:"waived"`
}

// Summarize tallies results by status.
func Summarize(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Pass++
		case StatusFail:
			s.Fail++
		case StatusError:
			s.Error++
		case StatusNotApplicable:
			s.NotApplicable++
		case StatusWaived:
			s.Waived++
		}
	}
	return s
}

// Score is the compliance percentage: passing checks over checks that actually
// applied.
//
// Errored, not-applicable and waived checks are excluded from the denominator.
// Counting an unreadable check as a failure would make the score drop when the
// agent loses a permission, which reads as a compliance regression that never
// happened; counting it as a pass would hide real gaps. Excluding it, and
// reporting the error count separately, is the only honest option.
func (s Summary) Score() float64 {
	denom := s.Pass + s.Fail
	if denom == 0 {
		return 0
	}
	return float64(s.Pass) / float64(denom) * 100
}
