package system

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// VulnerablePackage is one installed package that FreeBSD's pkg audit matched
// against the vulnerability database (VuXML), as OPNsense's own firmware
// audit shows it. Issue is the advisory's one-line description; CVEs and URL
// are what the person needs to judge it.
type VulnerablePackage struct {
	Name    string
	Version string
	Issue   string
	CVEs    []string
	URL     string
}

const maxIssueLen = 240
const maxCVEs = 10

// parsePkgAuditJSON reads `pkg audit --raw=json-compact`:
//
//	{"pkg_count":1,"packages":{"curl":{"version":"8.4.0","issue_count":1,
//	  "issues":[{"Affected versions":["< 8.5.0"],"description":"curl -- …",
//	  "cve":["CVE-2023-…"],"url":"https://vuxml.freebsd.org/…"}]}}}
//
// Keys are read leniently (cve or cves) so a pkg release that renames one
// still yields the package and its version.
func parsePkgAuditJSON(b []byte) ([]VulnerablePackage, error) {
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Issues  []struct {
				Description string   `json:"description"`
				CVE         []string `json:"cve"`
				CVEs        []string `json:"cves"`
				URL         string   `json:"url"`
			} `json:"issues"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("pkg audit json: %w", err)
	}
	out := make([]VulnerablePackage, 0, len(doc.Packages))
	for name, p := range doc.Packages {
		v := VulnerablePackage{Name: name, Version: p.Version}
		seen := map[string]bool{}
		for i, is := range p.Issues {
			if i == 0 {
				v.Issue = strings.TrimSpace(is.Description)
				v.URL = strings.TrimSpace(is.URL)
			}
			for _, c := range append(is.CVE, is.CVEs...) {
				c = strings.TrimSpace(c)
				if c != "" && !seen[c] && len(v.CVEs) < maxCVEs {
					seen[c] = true
					v.CVEs = append(v.CVEs, c)
				}
			}
		}
		if n := len(p.Issues); n > 1 {
			v.Issue = fmt.Sprintf("%s (and %d more)", v.Issue, n-1)
		}
		if len(v.Issue) > maxIssueLen {
			v.Issue = v.Issue[:maxIssueLen-1] + "…"
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// parsePkgAuditQuiet reads `pkg audit -q`: one name-version per line. The
// version is after the last dash (package names contain dashes, versions do
// not). Used when the JSON form is not available.
func parsePkgAuditQuiet(b []byte) []VulnerablePackage {
	var out []VulnerablePackage
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		v := VulnerablePackage{Name: line}
		if i := strings.LastIndex(line, "-"); i > 0 {
			v.Name, v.Version = line[:i], line[i+1:]
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// vulnerablePackageLabels is the label set of one system_vulnerable_package
// series.
func vulnerablePackageLabels(v VulnerablePackage) map[string]string {
	return map[string]string{
		"package": v.Name,
		"version": v.Version,
		"issue":   v.Issue,
		"cves":    strings.Join(v.CVEs, ","),
		"url":     v.URL,
	}
}
