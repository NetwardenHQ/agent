package k8s

import (
	"reflect"
	"testing"
)

// The cluster's own ingress host names, as the inventory reports them.
var clusterHosts = []string{
	"moriah.app", "www.moriah.app", "admin.moriah.app", "epistles.net", "api.epistles.net",
	"app.netwarden.com", "api.netwarden.com", "ingest.netwarden.com", "churchfoundry.com",
}

func TestClassifyTenTwentyThree(t *testing.T) {
	want := [][]Class{
		{ClassSecretFile, ClassCrawlerClaim},   // /.env
		{ClassSecretFile, ClassCrawlerClaim},   // /workspace/.env
		{ClassSecretFile, ClassCrawlerClaim},   // /.ssh/authorized_keys
		{ClassSecretFile, ClassCrawlerClaim},   // /.docker/config.json
		{ClassSecretFile, ClassCrawlerClaim},   // /values.yaml
		{ClassCrawlerClaim, ClassTargetedPath}, // /z9x8c7v6b5-debug-trigger-admin.moriah.app
		{ClassServerAction, ClassCrawlerClaim}, // POST / with Next-Action and text/x-component
		{ClassGraphQLProbe, ClassCrawlerClaim}, // POST /graphql answered 404
	}
	lines := readLines(t, "1023.log")
	if len(lines) != len(want) {
		t.Fatalf("%d lines, %d expectations", len(lines), len(want))
	}
	for i, raw := range lines {
		l, ok := ParseAccessLine(raw)
		if !ok {
			t.Fatalf("line %d not parsed", i+1)
		}
		if got := Classify(l, clusterHosts, false); !reflect.DeepEqual(got, want[i]) {
			t.Errorf("%s %s: got %v, want %v", l.Method, l.Path, got, want[i])
		}
	}
}

func TestClassifyNormalTraffic(t *testing.T) {
	// Two minutes of this cluster's real traffic, addresses and ids
	// anonymized. moriah.app serves server actions; nothing else here does.
	claims := 0
	for i, raw := range readLines(t, "normal.log") {
		l, ok := ParseAccessLine(raw)
		if !ok {
			t.Fatalf("line %d not parsed", i+1)
		}
		for _, c := range Classify(l, clusterHosts, l.Host == "moriah.app") {
			if c != ClassCrawlerClaim {
				t.Errorf("line %d (%s %s %s %d) classed %s", i+1, l.Host, l.Method, l.Path, l.Status, c)
				continue
			}
			claims++
		}
	}
	// The sample holds real Googlebot, ClaudeBot and APIs-Google visits. A
	// crawler name is a claim the platform checks, not a finding.
	if claims == 0 {
		t.Error("the sample's crawler visits were not seen as crawler claims")
	}
}

func classesOf(method, path string, status int) []Class {
	return Classify(AccessLine{Method: method, Path: path, Status: status, Full: true, Host: "shop.example"}, clusterHosts, false)
}

func TestClassifySignatures(t *testing.T) {
	cases := []struct {
		method, path string
		status       int
		want         []Class
	}{
		{"GET", "/.env", 404, []Class{ClassSecretFile}},
		{"GET", "/.ENV.production", 404, []Class{ClassSecretFile}},
		{"GET", "/app/.git/config", 404, []Class{ClassSecretFile}},
		{"GET", "/.git", 404, []Class{ClassSecretFile}},
		{"GET", "/.aws/credentials", 404, []Class{ClassSecretFile}},
		{"GET", "/credentials.json", 404, []Class{ClassSecretFile}},
		{"GET", "/backup.SQL", 404, []Class{ClassSecretFile}},
		{"GET", "/id_rsa.pub", 404, []Class{ClassSecretFile}},
		{"GET", "/docker-compose.prod.yml", 404, []Class{ClassSecretFile}},
		{"GET", "/secrets.yaml", 404, []Class{ClassSecretFile}},
		{"GET", "/wp-config.php.bak", 404, []Class{ClassSecretFile}},
		{"GET", "/.DS_Store", 404, []Class{ClassSecretFile}},
		{"GET", "/%2e%65nv", 404, []Class{ClassSecretFile}},
		{"GET", "/static/../.env", 404, []Class{ClassSecretFile}},
		{"GET", "//.env", 404, []Class{ClassSecretFile}},
		{"GET", "/wp-login.php", 404, []Class{ClassAdminProbe, ClassExploitPath}},
		{"GET", "/wp-login.php", 200, []Class{ClassAdminProbe}},
		{"GET", "/phpmyadmin/index.php", 404, []Class{ClassAdminProbe, ClassExploitPath}},
		{"GET", "/actuator/env", 404, []Class{ClassAdminProbe}},
		{"GET", "/manager/html", 404, []Class{ClassAdminProbe}},
		{"GET", "/cgi-bin/luci", 404, []Class{ClassExploitPath}},
		{"GET", "/a/b/etc/passwd", 400, []Class{ClassExploitPath}},
		{"GET", "/proc/self/environ", 404, []Class{ClassExploitPath}},
		{"GET", "/c:/windows/win.ini", 404, []Class{ClassExploitPath}},
		{"GET", "/index.php", 404, []Class{ClassExploitPath}},
		{"GET", "/index.php", 200, nil},
		{"POST", "/graphql", 404, []Class{ClassGraphQLProbe}},
		{"POST", "/api/graphql", 404, []Class{ClassGraphQLProbe}},
		{"POST", "/graphql", 200, nil},
		{"GET", "/graphql", 404, nil},
		{"GET", "/z9x8-debug.moriah.app", 404, []Class{ClassTargetedPath}},
		// Routes that only look like secrets.
		{"GET", "/settings/credentials", 200, nil},
		{"GET", "/api/accounts/x/access-token", 200, nil},
		{"GET", "/environment", 200, nil},
		{"GET", "/blog/key-dates", 200, nil},
		{"GET", "/admin/console", 200, nil},
		{"GET", "/", 200, nil},
	}
	for _, c := range cases {
		if got := classesOf(c.method, c.path, c.status); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %s %d: got %v, want %v", c.method, c.path, c.status, got, c.want)
		}
	}
}

func TestServerActionNeedsFullFormat(t *testing.T) {
	l := AccessLine{Method: "POST", Path: "/", Status: 200, NextAction: "x", ContentType: "text/x-component"}
	if got := Classify(l, nil, false); len(got) != 0 {
		t.Errorf("default-format line classed %v", got)
	}
	l.Full = true
	if got := Classify(l, nil, false); !reflect.DeepEqual(got, []Class{ClassServerAction}) {
		t.Errorf("full line classed %v", got)
	}
}

func TestServerActionOffWhenAppServesThem(t *testing.T) {
	l := AccessLine{Method: "POST", Path: "/", Status: 200, NextAction: "x", RSC: "1", Full: true}
	if got := Classify(l, nil, true); len(got) != 0 {
		t.Errorf("an app that serves server actions: classed %v", got)
	}
	// A Next.js navigation sends RSC: 1 on GET; that is never a server action.
	nav := AccessLine{Method: "GET", Path: "/people", Status: 200, RSC: "1", Full: true}
	if got := Classify(nav, nil, false); len(got) != 0 {
		t.Errorf("navigation classed %v", got)
	}
}

func TestCrawlerClaims(t *testing.T) {
	cases := map[string][]string{
		"CCBot/2.0 (https://commoncrawl.org/faq/)": {"CCBot"},
		"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.122 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": {"Googlebot"},
		"Googlebot-Image/1.0": {"Googlebot"},
		"Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot) CCBot/2.0":                                      {"GPTBot", "CCBot"},
		"APIs-Google (+https://developers.google.com/webmasters/APIs-Google.html)":                                        {"APIs-Google"},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36": nil,
		"": nil,
	}
	for ua, want := range cases {
		if got := CrawlerClaims(ua); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, want %v", ua, got, want)
		}
	}
}

func TestCrawlerListLoads(t *testing.T) {
	if len(crawlerTokens) < 20 {
		t.Fatalf("crawlers.json gave %d names", len(crawlerTokens))
	}
}
