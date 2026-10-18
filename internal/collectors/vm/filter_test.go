//go:build linux

package vm

import "testing"

func TestFilterVMs(t *testing.T) {
	vms := []VM{{Name: "prod-web"}, {Name: "prod-db"}, {Name: "test-web"}, {Name: "dev-1"}}
	names := func(vms []VM) []string {
		out := make([]string, len(vms))
		for i, v := range vms {
			out[i] = v.Name
		}
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	if got := names(filterVMs(vms, nil, nil)); !eq(got, []string{"prod-web", "prod-db", "test-web", "dev-1"}) {
		t.Errorf("no filters: %v", got)
	}
	if got := names(filterVMs(vms, []string{"prod-*"}, nil)); !eq(got, []string{"prod-web", "prod-db"}) {
		t.Errorf("include: %v", got)
	}
	if got := names(filterVMs(vms, nil, []string{"test-*", "dev-*"})); !eq(got, []string{"prod-web", "prod-db"}) {
		t.Errorf("exclude: %v", got)
	}
	if got := names(filterVMs(vms, []string{"*-web"}, []string{"test-*"})); !eq(got, []string{"prod-web"}) {
		t.Errorf("include then exclude: %v", got)
	}
}
