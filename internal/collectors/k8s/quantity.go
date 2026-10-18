package k8s

import (
	"math"
	"strconv"
	"strings"
)

/*
Kubernetes resource quantities are strings with a suffix, and metrics.k8s.io
reports CPU in nanocores ("123456789n") and memory in binary SI ("1234Ki").
There is no float in the wire format, so every value has to be parsed here.

k8s.io/apimachinery's resource.Quantity is not used: this collector talks to
the API server over plain HTTPS without client-go, and importing apimachinery
for one parser would undo that.
*/

// binarySuffixes are powers of 1024; decimalSuffixes are powers of 1000.
var binarySuffixes = map[string]float64{
	"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50, "Ei": 1 << 60,
}

var decimalSuffixes = map[string]float64{
	"n": 1e-9, "u": 1e-6, "m": 1e-3,
	"":  1,
	"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
}

// parseQuantity converts a Kubernetes quantity to a plain float in the
// quantity's own base unit: cores for CPU, bytes for memory/storage.
//
// It returns 0, false for anything it cannot read. Callers treat that as "no
// reading", never as zero usage, because a silently zero CPU chart is worse
// than a gap.
func parseQuantity(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}

	i := 0
	for i < len(s) && (s[i] == '-' || s[i] == '+' || s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	head, suffix := s[:i], s[i:]
	if head == "" {
		return 0, false
	}

	n, err := strconv.ParseFloat(head, 64)
	if err != nil {
		return 0, false
	}

	// Exponent form, e.g. "1e3". A bare "E" is not an exponent: it is the exa
	// suffix, handled with the others below. A bare "e" is malformed.
	if suffix == "e" {
		return 0, false
	}
	if len(suffix) > 1 && (suffix[0] == 'e' || suffix[0] == 'E') {
		exp, err := strconv.Atoi(suffix[1:])
		if err != nil {
			return 0, false
		}
		// math.Pow10 is constant-time and saturates to +Inf or 0 for absurd
		// exponents; an infinite result is not a reading.
		v := n * math.Pow10(exp)
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return 0, false
		}
		return v, true
	}

	if mult, ok := binarySuffixes[suffix]; ok {
		return n * mult, true
	}
	if mult, ok := decimalSuffixes[suffix]; ok {
		return n * mult, true
	}
	return 0, false
}
