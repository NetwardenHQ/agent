package selfupdate

import (
	"fmt"
	"strconv"
	"strings"
)

// parsed is a version split into numeric release segments and an optional
// pre-release tag. Both published spellings are handled: Debian writes
// 3.0.0~beta, semver writes 3.0.0-beta.
type parsed struct {
	nums []int
	pre  string
	ok   bool
}

func parseVersion(v string) parsed {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return parsed{}
	}

	pre := ""
	if i := strings.IndexAny(s, "-~"); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	if s == "" {
		return parsed{}
	}

	fields := strings.Split(s, ".")
	nums := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 {
			return parsed{}
		}
		nums = append(nums, n)
	}
	return parsed{nums: nums, pre: pre, ok: true}
}

// CompareVersions reports -1 if a < b, 0 if equal, 1 if a > b.
//
// The server applies the same ordering when it decides whether to offer an
// update at all. If the two disagree, an agent can be told to update forever
// or never, so the rules are part of the contract: segments compare
// numerically (1.0.10 > 1.0.6), a pre-release sorts before its release, and
// anything unparseable compares equal.
func CompareVersions(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	if !pa.ok || !pb.ok {
		return 0
	}

	n := len(pa.nums)
	if len(pb.nums) > n {
		n = len(pb.nums)
	}
	for i := 0; i < n; i++ {
		na, nb := 0, 0
		if i < len(pa.nums) {
			na = pa.nums[i]
		}
		if i < len(pb.nums) {
			nb = pb.nums[i]
		}
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
	}

	switch {
	case pa.pre == pb.pre:
		return 0
	case pa.pre == "": // a release beats its own pre-release
		return 1
	case pb.pre == "":
		return -1
	case pa.pre < pb.pre:
		return -1
	default:
		return 1
	}
}

// checkInstallerVersion is the downgrade guard that does not trust the reply.
//
// The offered version string is only a claim: a forged or replayed reply can
// pair "99.0.0" with an older, genuinely signed release installer, and the
// signature check alone would pass it. The version embedded
// in the installer is covered by that signature, so after verification it is
// the authoritative one. It must be exactly the version offered, and newer
// than what is running.
func checkInstallerVersion(embedded, offered, current string) error {
	embedded = strings.TrimSpace(embedded)
	if embedded == "" {
		return fmt.Errorf("installer carries no version")
	}
	if embedded != offered {
		return fmt.Errorf("installer is version %q, but %q was offered", embedded, offered)
	}
	if CompareVersions(embedded, current) <= 0 {
		return fmt.Errorf("installer version %q is not newer than running %q", embedded, current)
	}
	return nil
}
