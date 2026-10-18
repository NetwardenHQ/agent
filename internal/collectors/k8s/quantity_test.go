package k8s

import (
	"testing"
	"time"
)

func TestParseQuantity(t *testing.T) {
	cases := []struct {
		in   string
		want float64
		ok   bool
	}{
		// CPU as metrics.k8s.io reports it: nanocores.
		{"123456789n", 0.123456789, true},
		{"1500m", 1.5, true},
		{"2", 2, true},
		{"0", 0, true},
		// Memory / storage, binary SI.
		{"1234Ki", 1234 * 1024, true},
		{"2Gi", 2 * 1073741824, true},
		{"1Mi", 1048576, true},
		// Decimal SI still appears on capacity fields.
		{"500M", 500e6, true},
		{"1k", 1000, true},
		// Exponent form is legal in the quantity grammar.
		{"1e3", 1000, true},
		// Plain bytes.
		{"4096", 4096, true},
		// Unreadable input reports "no reading", never 0.
		{"", 0, false},
		{"abc", 0, false},
		{"12Xi", 0, false},
		{"Ki", 0, false},
	}
	for _, c := range cases {
		got, ok := parseQuantity(c.in)
		if ok != c.ok {
			t.Errorf("parseQuantity(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && !almost(got, c.want) {
			t.Errorf("parseQuantity(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func almost(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	// Relative for large values, absolute for small ones.
	scale := b
	if scale < 0 {
		scale = -scale
	}
	if scale < 1 {
		return d < 1e-9
	}
	return d/scale < 1e-9
}

// "E" alone is the exa suffix, not a malformed exponent. An absurd exponent is
// "no reading" and is rejected in constant time.
func TestParseQuantityExaAndHugeExponents(t *testing.T) {
	if v, ok := parseQuantity("2E"); !ok || !almost(v, 2e18) {
		t.Errorf(`parseQuantity("2E") = %v, %v; want 2e18`, v, ok)
	}
	start := time.Now()
	for _, in := range []string{"1e999999999", "1E999999999", "1e99999999999999999999"} {
		if v, ok := parseQuantity(in); ok {
			t.Errorf("parseQuantity(%q) = %v, want no reading", in, v)
		}
	}
	if v, ok := parseQuantity("5e-999999999"); !ok || v != 0 {
		t.Errorf("a vanishingly small quantity is a real zero, got %v, %v", v, ok)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("huge exponents took %v; must be constant-time", elapsed)
	}
}
