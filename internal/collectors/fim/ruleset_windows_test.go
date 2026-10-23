//go:build windows

package fim

import (
	"slices"
	"testing"
)

func TestWindowsRulesetNonEmpty(t *testing.T) {
	roots := defaultRoots(ScopeCredentials)
	if !slices.Equal(roots, defaultRoots(ScopeFull)) {
		t.Fatal("windows scopes differ; the ruleset has no costly part to leave out")
	}
	if len(roots) == 0 {
		t.Fatal("windows default ruleset is empty; FIM would be inert")
	}
	for _, r := range roots {
		if len(r) < 3 || r[1] != ':' {
			t.Errorf("expected an absolute windows path, got %q", r)
		}
	}
}
