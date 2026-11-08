package k8s

import (
	_ "embed"
	"encoding/json"
	"net/url"
	"path"
	"sort"
	"strings"
)

/*
Signatures: what a single request says about its sender, with no state.

A request matches zero or more classes. Nothing here decides whether an
address is an attacker; a drive-by request for /.env is common background
noise. The platform weighs classes across requests, hosts and customers.

Matching is on the normalized path: percent-decoded, dot segments resolved,
repeated slashes merged, lowercased. Scanners spell the same path many ways
and the default log format records it undecoded.

SignatureVersion changes whenever a list changes, and is reported with every
event, so a finding can say which rules produced it.
*/

// SignatureVersion identifies the lists below.
const SignatureVersion = "2026-10-23.1"

// Class is what a request was probing for.
type Class string

const (
	ClassSecretFile   Class = "secret_file"
	ClassAdminProbe   Class = "admin_probe"
	ClassExploitPath  Class = "exploit_path"
	ClassServerAction Class = "server_action"
	ClassGraphQLProbe Class = "graphql_probe"
	ClassCrawlerClaim Class = "crawler_claim"
	ClassTargetedPath Class = "targeted_path"
)

var (
	// Directory names that are never meant to be served.
	secretDirs = map[string]bool{".git": true, ".svn": true, ".hg": true, ".ssh": true, ".aws": true}
	// Exact file names.
	secretNames = map[string]bool{
		".npmrc": true, ".pypirc": true, ".htpasswd": true, "values.yaml": true, "web.config": true, ".ds_store": true,
	}
	// Extensions of keys, dumps and editor or backup copies.
	secretExts = map[string]bool{
		".pem": true, ".key": true, ".p12": true, ".pfx": true, ".sql": true, ".sqlite": true,
		".bak": true, ".old": true, ".swp": true,
	}

	// Admin consoles. The WordPress and PHP ones are distinctive enough to
	// match at any depth; the generic names only at the root, where scanners
	// look for them, so an app's own /admin/console route is left alone.
	adminAnywhere = map[string]bool{
		"wp-admin": true, "wp-login.php": true, "xmlrpc.php": true, "phpmyadmin": true, "phpinfo.php": true,
	}
	adminAtRoot = map[string]bool{"server-status": true, "actuator": true, "console": true, "solr": true, "jenkins": true}

	graphqlPaths = map[string]bool{"/graphql": true, "/api/graphql": true, "/v1/graphql": true}
)

// Classify returns the classes a request matches, in a fixed order.
// ownHosts are the cluster's Ingress host names; servesServerActions says
// whether the request's ingress is known to serve Next.js server actions.
func Classify(l AccessLine, ownHosts []string, servesServerActions bool) []Class {
	p := normalizePath(l.Path)
	segs := strings.Split(strings.Trim(p, "/"), "/")
	base := segs[len(segs)-1]

	var out []Class
	if isSecretFile(segs, base) {
		out = append(out, ClassSecretFile)
	}
	if adminAtRoot[segs[0]] || (len(segs) > 1 && segs[0] == "manager" && segs[1] == "html") || anySegment(segs, adminAnywhere) {
		out = append(out, ClassAdminProbe)
	}
	if isExploitPath(p, segs, base, l.Status) {
		out = append(out, ClassExploitPath)
	}
	// Only a JSON line records the headers, and an app that serves server
	// actions receives these POSTs all day: there, only the app can tell a
	// probe from a click.
	if l.Full && !servesServerActions && l.Method == "POST" &&
		(l.NextAction != "" || l.RSC != "" || strings.Contains(strings.ToLower(l.ContentType), "text/x-component")) {
		out = append(out, ClassServerAction)
	}
	if l.Method == "POST" && l.Status == 404 && graphqlPaths[p] {
		out = append(out, ClassGraphQLProbe)
	}
	if len(CrawlerClaims(l.UserAgent)) > 0 {
		out = append(out, ClassCrawlerClaim)
	}
	if mentionsOwnHost(p, ownHosts) {
		out = append(out, ClassTargetedPath)
	}
	return out
}

func normalizePath(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	return path.Clean("/" + strings.ToLower(p))
}

func anySegment(segs []string, names map[string]bool) bool {
	for _, s := range segs {
		if names[s] {
			return true
		}
	}
	return false
}

func isSecretFile(segs []string, base string) bool {
	for i, s := range segs {
		if secretDirs[s] {
			return true
		}
		if s == ".docker" && i+1 < len(segs) && segs[i+1] == "config.json" {
			return true
		}
	}
	ext := path.Ext(base)
	yaml := ext == ".yml" || ext == ".yaml"
	switch {
	case strings.HasPrefix(base, ".env"), secretNames[base], secretExts[ext]:
		return true
	case strings.HasPrefix(base, "id_rsa"), strings.HasPrefix(base, "wp-config.php"):
		return true
	case strings.HasPrefix(base, "docker-compose") && yaml:
		return true
	case strings.HasPrefix(base, "secrets") && (yaml || ext == ".json"):
		return true
	// An extension is required: /settings/credentials is a page, not a file.
	case strings.HasPrefix(base, "credentials."):
		return true
	}
	return false
}

func isExploitPath(p string, segs []string, base string, status int) bool {
	if strings.Contains(p, "/etc/passwd") || strings.Contains(p, "/proc/self") || strings.Contains(p, "win.ini") {
		return true
	}
	for _, s := range segs {
		if s == "cgi-bin" {
			return true
		}
	}
	// PHP on a site that answers 404: someone looking for a PHP app to break.
	return status == 404 && (strings.HasSuffix(base, ".php") || strings.Contains(p, ".php/"))
}

// mentionsOwnHost catches paths built from the target's own name, a common
// way scanners guess at debug and admin routes.
func mentionsOwnHost(p string, ownHosts []string) bool {
	for _, h := range ownHosts {
		h = strings.ToLower(h)
		if len(h) >= 4 && !strings.HasPrefix(h, "*") && strings.Contains(p, h) {
			return true
		}
	}
	return false
}

// crawlers.json lists the crawler names the platform can verify, by the
// operator that publishes them. It is shared with the platform, which checks
// the two agree.
//
//go:embed crawlers.json
var crawlersJSON []byte

type crawlerList struct {
	Version  string `json:"version"`
	Crawlers []struct {
		Operator string   `json:"operator"`
		Claims   []string `json:"claims"`
	} `json:"crawlers"`
}

// crawlerTokens holds every name in file order; crawlerSearch is the same
// names, lowercased, longest first.
var crawlerTokens, crawlerSearch = loadCrawlers()

func loadCrawlers() ([]string, []string) {
	var list crawlerList
	if err := json.Unmarshal(crawlersJSON, &list); err != nil {
		panic("crawlers.json: " + err.Error())
	}
	var tokens []string
	for _, c := range list.Crawlers {
		tokens = append(tokens, c.Claims...)
	}
	search := append([]string(nil), tokens...)
	sort.SliceStable(search, func(i, j int) bool { return len(search[i]) > len(search[j]) })
	return tokens, search
}

// CrawlerClaims returns the crawler names a user agent uses, in list order.
// Longer names are matched first and removed, so "Googlebot-Image" is
// Googlebot and "Claude-User" is not also ClaudeBot.
func CrawlerClaims(userAgent string) []string {
	if userAgent == "" {
		return nil
	}
	ua := strings.ToLower(userAgent)
	found := map[string]bool{}
	for _, name := range crawlerSearch {
		token := strings.ToLower(name)
		if strings.Contains(ua, token) {
			found[name] = true
			ua = strings.ReplaceAll(ua, token, " ")
		}
	}
	var out []string
	for _, name := range crawlerTokens {
		if found[name] {
			out = append(out, name)
		}
	}
	return out
}
