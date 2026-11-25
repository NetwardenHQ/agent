package system

import (
	"reflect"
	"testing"
)

func TestParsePkgAuditJSON(t *testing.T) {
	raw := []byte(`{"pkg_count":2,"packages":{
	  "py311-urllib3":{"version":"2.2.1","issue_count":1,"issues":[
	    {"Affected versions":["< 2.2.2"],"description":"py-urllib3 -- proxy-authorization header kept across origins","cve":["CVE-2024-37891"],"url":"https://vuxml.freebsd.org/freebsd/abc.html"}]},
	  "curl":{"version":"8.10.0","issue_count":2,"issues":[
	    {"description":"curl -- netrc and redirect credential leak","cves":["CVE-2024-11053"],"url":"https://vuxml.freebsd.org/freebsd/def.html"},
	    {"description":"curl -- second issue","cve":["CVE-2024-11053","CVE-2024-9681"],"url":"https://vuxml.freebsd.org/freebsd/ghi.html"}]}}}`)
	got, err := parsePkgAuditJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []VulnerablePackage{
		{Name: "curl", Version: "8.10.0", Issue: "curl -- netrc and redirect credential leak (and 1 more)", CVEs: []string{"CVE-2024-11053", "CVE-2024-9681"}, URL: "https://vuxml.freebsd.org/freebsd/def.html"},
		{Name: "py311-urllib3", Version: "2.2.1", Issue: "py-urllib3 -- proxy-authorization header kept across origins", CVEs: []string{"CVE-2024-37891"}, URL: "https://vuxml.freebsd.org/freebsd/abc.html"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestParsePkgAuditJSONRejectsText(t *testing.T) {
	if _, err := parsePkgAuditJSON([]byte("curl-8.10.0 is vulnerable:\n")); err == nil {
		t.Fatal("plain text parsed as JSON")
	}
}

func TestParsePkgAuditQuiet(t *testing.T) {
	got := parsePkgAuditQuiet([]byte("py311-urllib3-2.2.1\ncurl-8.10.0\n\n"))
	want := []VulnerablePackage{{Name: "curl", Version: "8.10.0"}, {Name: "py311-urllib3", Version: "2.2.1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestVulnerablePackageLabels(t *testing.T) {
	l := vulnerablePackageLabels(VulnerablePackage{Name: "curl", Version: "8.10.0", Issue: "x", CVEs: []string{"CVE-1", "CVE-2"}, URL: "u"})
	if l["package"] != "curl" || l["version"] != "8.10.0" || l["cves"] != "CVE-1,CVE-2" || l["url"] != "u" || l["issue"] != "x" {
		t.Fatalf("labels = %v", l)
	}
}
