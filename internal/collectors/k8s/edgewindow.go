package k8s

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/NetwardenHQ/agent/internal/spool"
)

/*
Edge windows: what each client address did during one reporting cycle.

Every request is counted against its address, but only an address that
matched a signature class leaves the agent, as one web.probe event per cycle.
Normal traffic is never reported: its addresses, paths and user agents are
dropped when the window closes. Private, loopback, CGNAT and link-local
addresses are not tracked at all.

Two things are remembered across cycles, per ingress, to judge a single
request:

  - The not-found shape: the most common response size (and type, in the
    JSON format) among 404s and among 2xx answers to probe paths. A
    single-page app answers /.env with its index page; the shape is how that
    is told apart from a file that was really served.
  - Whether the ingress serves Next.js server actions: a POST with a
    Next-Action header answered 2xx from at least serverActionLearnAddresses
    addresses within serverActionLearnDays. Until an ingress has been watched
    that long, and for one that does serve them, server_action is not raised
    from the log: only the app can tell a probe from a click.

Both are saved under <spool>/edge/state.json, so a container restart does
not start them over. Addresses in that file are hashed: it records that
someone used server actions, not who.

A secret file answered 2xx becomes a web.exposure event at once, and urgent
asks the agent to report without waiting for the cycle.
*/

const (
	maxTrackedAddresses        = 20000
	maxProbeEventsPerCycle     = 100
	maxEventPaths              = 20
	labelMax                   = 300
	notFoundTolerance          = 0.10
	serverActionLearnAddresses = 10
	serverActionLearnDays      = 7
	urgentMinInterval          = 30 * time.Second

	maxSourceHosts      = 20
	maxSourceAgents     = 20
	maxSourcePathHashes = 1000
	maxShapeSizes       = 32
	shapeMinSamples     = 3
	shapeMaxCount       = 1000
	maxLearnedAddresses = 64
	maxTitleRunes       = 200
	edgeStateVersion    = 1
)

var classOrder = []Class{
	ClassSecretFile, ClassAdminProbe, ClassExploitPath, ClassServerAction, ClassGraphQLProbe, ClassCrawlerClaim, ClassTargetedPath,
}

// classWords is how titles name each class; the platform uses the same words.
var classWords = map[Class]string{
	ClassSecretFile: "secret files", ClassAdminProbe: "admin pages", ClassExploitPath: "exploit paths",
	ClassServerAction: "server actions", ClassGraphQLProbe: "GraphQL", ClassCrawlerClaim: "crawler names",
	ClassTargetedPath: "your host names",
}

// Classes whose 2xx answers teach the not-found shape: real sites rarely
// serve these paths, so what answers them is usually a catch-all page.
var probeClasses = map[Class]bool{ClassSecretFile: true, ClassAdminProbe: true, ClassExploitPath: true}

type statusCount struct{ status, n int }

type edgeSource struct {
	ip           string
	requests     int
	notFound     int
	hosts        []string
	classes      uint8 // bit i is classOrder[i]
	paths        []string
	pathHashes   map[uint64]struct{}
	statuses     []statusCount
	claims       []string
	agents       []uint64
	agentSample  string
	sawDefault   bool
	flagged      bool
	unflaggedPos *list.Element
}

type notFoundShape struct {
	Sizes map[int64]int  `json:"sizes"`
	Types map[string]int `json:"types,omitempty"`
}

func (s *notFoundShape) add(size int64, typ string) {
	if s.Sizes == nil {
		s.Sizes = map[int64]int{}
	}
	if _, ok := s.Sizes[size]; !ok && len(s.Sizes) >= maxShapeSizes {
		var least int64
		first := true
		for k, n := range s.Sizes {
			if first || n < s.Sizes[least] {
				least, first = k, false
			}
		}
		delete(s.Sizes, least)
	}
	s.Sizes[size]++
	if typ != "" {
		if s.Types == nil {
			s.Types = map[string]int{}
		}
		if _, ok := s.Types[typ]; ok || len(s.Types) < maxShapeSizes {
			s.Types[typ]++
		}
	}
	// Halve the counts now and then, so the shape follows a site that changes.
	if s.Sizes[size] > shapeMaxCount {
		for k := range s.Sizes {
			s.Sizes[k] /= 2
		}
		for k := range s.Types {
			s.Types[k] /= 2
		}
	}
}

// mode is the most common size and type, and how often that size was seen.
func (s *notFoundShape) mode() (size int64, typ string, n int) {
	if s == nil {
		return 0, "", 0
	}
	for k, c := range s.Sizes {
		if c > n || (c == n && k < size) {
			size, n = k, c
		}
	}
	best := 0
	for k, c := range s.Types {
		if c > best || (c == best && k < typ) {
			typ, best = k, c
		}
	}
	return size, typ, n
}

type actionLearning struct {
	FirstSeen time.Time            `json:"first_seen"`
	Addresses map[string]time.Time `json:"action_addresses,omitempty"`
}

// edgeStats is one cycle's counts, for the k8s_ingress_log_* metrics.
type edgeStats struct {
	Lines, Unparsed, Flagged, Dropped int
	GapSeconds                        float64
}

// blindIngress is an ingress and why server_action cannot be raised from its
// log; Reason is empty when it can.
type blindIngress struct {
	Ingress, Reason string
}

type edgeTracker struct {
	mu        sync.Mutex
	max       int
	sources   map[string]*edgeSource
	unflagged *list.List // of *edgeSource, oldest first
	shapes    map[string]*notFoundShape
	actions   map[string]*actionLearning
	exposures []spool.Event

	windowStart time.Time
	lines       int
	unparsed    int
	lastUrgent  time.Time
	now         func() time.Time
	urgent      func()
}

func newEdgeTracker(maxAddresses int) *edgeTracker {
	return &edgeTracker{
		max:         maxAddresses,
		sources:     map[string]*edgeSource{},
		unflagged:   list.New(),
		shapes:      map[string]*notFoundShape{},
		actions:     map[string]*actionLearning{},
		windowStart: time.Now(),
		now:         time.Now,
	}
}

// logIngressKey names the ingress a line belongs to: namespace/name in the JSON
// format, the upstream in the default one.
func logIngressKey(l AccessLine) string {
	if l.Namespace != "" && l.Ingress != "" {
		return l.Namespace + "/" + l.Ingress
	}
	return l.Upstream
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func trackable(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return !(a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || cgnat.Contains(a))
}

func has(classes []Class, c Class) bool {
	for _, x := range classes {
		if x == c {
			return true
		}
	}
	return false
}

func isHTML(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "text/html")
}

// CountUnparsed records a line that was neither a request nor a controller
// message.
func (t *edgeTracker) CountUnparsed() {
	t.mu.Lock()
	t.unparsed++
	t.mu.Unlock()
}

// Observe records one request and the classes it matched.
func (t *edgeTracker) Observe(l AccessLine, classes []Class) {
	fire := false
	t.mu.Lock()
	t.lines++
	key := logIngressKey(l)

	exposed := false
	if has(classes, ClassSecretFile) && l.Status >= 200 && l.Status < 300 {
		if verdict := t.verdict(l, key); verdict != "" {
			t.exposures = append(t.exposures, t.exposureEvent(l, key, verdict))
			exposed = true
			if t.urgent != nil {
				if now := t.now(); t.lastUrgent.IsZero() || now.Sub(t.lastUrgent) >= urgentMinInterval {
					t.lastUrgent = now
					fire = true
				}
			}
		}
	}
	t.learn(l, key, classes, exposed)
	if trackable(l.IP) {
		t.count(l, classes)
	}
	t.mu.Unlock()
	if fire {
		t.urgent()
	}
}

// verdict judges a secret-file path answered 2xx: "likely" when the response
// type says it is not a web page and the not-found shape does not explain it,
// "possible" when only the size differs from the shape, "" otherwise.
func (t *edgeTracker) verdict(l AccessLine, key string) string {
	size, typ, n := t.shapes[key].mode()
	known := n >= shapeMinSamples
	near := known && float64(abs(l.Bytes-size)) <= notFoundTolerance*float64(size)
	if l.Full && l.ResponseType != "" && !isHTML(l.ResponseType) {
		// An API that answers every unknown path the same way is not leaking.
		if near && strings.EqualFold(l.ResponseType, typ) {
			return ""
		}
		return "likely"
	}
	if !known || near {
		return ""
	}
	return "possible"
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func (t *edgeTracker) learn(l AccessLine, key string, classes []Class, exposed bool) {
	if key == "" {
		return
	}
	probe := false
	for _, c := range classes {
		probe = probe || probeClasses[c]
	}
	if !exposed && (l.Status == 404 || (probe && l.Status >= 200 && l.Status < 300)) {
		s := t.shapes[key]
		if s == nil {
			s = &notFoundShape{}
			t.shapes[key] = s
		}
		typ := ""
		if l.Full {
			typ = l.ResponseType
		}
		s.add(l.Bytes, typ)
	}
	if !l.Full {
		return
	}
	a := t.actions[key]
	if a == nil {
		a = &actionLearning{FirstSeen: l.Time}
		t.actions[key] = a
	}
	if l.Method == "POST" && l.NextAction != "" && l.Status >= 200 && l.Status < 300 {
		if a.Addresses == nil {
			a.Addresses = map[string]time.Time{}
		}
		h := hashAddress(l.IP)
		if _, ok := a.Addresses[h]; !ok && len(a.Addresses) >= maxLearnedAddresses {
			var oldest string
			for k, at := range a.Addresses {
				if oldest == "" || at.Before(a.Addresses[oldest]) {
					oldest = k
				}
			}
			delete(a.Addresses, oldest)
		}
		a.Addresses[h] = l.Time
	}
}

func hashAddress(ip string) string {
	sum := sha256.Sum256([]byte("netwarden-edge:" + ip))
	return hex.EncodeToString(sum[:8])
}

// ServerActionBlind reports whether server_action must not be raised from
// the log of l's ingress at now, and why: "learning" (watched for less than
// serverActionLearnDays) or "serves_actions".
func (t *edgeTracker) ServerActionBlind(l AccessLine, now time.Time) (bool, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.blind(t.actions[logIngressKey(l)], now)
}

func (t *edgeTracker) blind(a *actionLearning, now time.Time) (bool, string) {
	if a == nil {
		return true, "learning"
	}
	window := serverActionLearnDays * 24 * time.Hour
	recent := 0
	for _, at := range a.Addresses {
		if now.Sub(at) <= window {
			recent++
		}
	}
	if recent >= serverActionLearnAddresses {
		return true, "serves_actions"
	}
	if now.Sub(a.FirstSeen) < window {
		return true, "learning"
	}
	return false, ""
}

// BlindIngresses lists every ingress seen in the JSON format, with its reason.
func (t *edgeTracker) BlindIngresses(now time.Time) []blindIngress {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]blindIngress, 0, len(t.actions))
	for key, a := range t.actions {
		_, reason := t.blind(a, now)
		out = append(out, blindIngress{Ingress: key, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ingress < out[j].Ingress })
	return out
}

func (t *edgeTracker) tracked() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sources)
}

func (t *edgeTracker) count(l AccessLine, classes []Class) {
	s := t.sources[l.IP]
	if s == nil {
		if len(t.sources) >= t.max {
			// Full: make room by forgetting the oldest address that matched
			// nothing. If every tracked address matched something, the new
			// one is not tracked.
			front := t.unflagged.Front()
			if front == nil {
				return
			}
			victim := t.unflagged.Remove(front).(*edgeSource)
			delete(t.sources, victim.ip)
		}
		s = &edgeSource{ip: l.IP}
		t.sources[l.IP] = s
		s.unflaggedPos = t.unflagged.PushBack(s)
	} else if s.unflaggedPos != nil {
		t.unflagged.MoveToBack(s.unflaggedPos)
	}

	s.requests++
	if l.Status == 404 {
		s.notFound++
	}
	if !l.Full {
		s.sawDefault = true
	}
	if l.Host != "" && len(s.hosts) < maxSourceHosts && !slices.Contains(s.hosts, l.Host) {
		s.hosts = append(s.hosts, l.Host)
	}
	found := false
	for i := range s.statuses {
		if s.statuses[i].status == l.Status {
			s.statuses[i].n++
			found = true
			break
		}
	}
	if !found {
		s.statuses = append(s.statuses, statusCount{l.Status, 1})
	}
	if l.UserAgent != "" {
		h := fnv.New64a()
		_, _ = h.Write([]byte(l.UserAgent))
		sum := h.Sum64()
		seen := false
		for _, a := range s.agents {
			seen = seen || a == sum
		}
		if !seen && len(s.agents) < maxSourceAgents {
			s.agents = append(s.agents, sum)
		}
		if s.agentSample == "" {
			s.agentSample = truncateRunes(l.UserAgent, labelMax)
		}
	}

	if len(classes) == 0 {
		return
	}
	for i, c := range classOrder {
		if has(classes, c) {
			s.classes |= 1 << i
		}
	}
	if has(classes, ClassCrawlerClaim) {
		for _, name := range CrawlerClaims(l.UserAgent) {
			if !slices.Contains(s.claims, name) {
				s.claims = append(s.claims, name)
			}
		}
	}
	if classes[0] != ClassCrawlerClaim || len(classes) > 1 {
		// A matched path: kept for the event, counted even past the cap.
		h := fnv.New64a()
		_, _ = h.Write([]byte(l.Path))
		if s.pathHashes == nil {
			s.pathHashes = map[uint64]struct{}{}
		}
		if _, ok := s.pathHashes[h.Sum64()]; !ok && len(s.pathHashes) < maxSourcePathHashes {
			s.pathHashes[h.Sum64()] = struct{}{}
			if len(s.paths) < maxEventPaths {
				s.paths = append(s.paths, l.Path)
			}
		}
	}
	if !s.flagged {
		s.flagged = true
		t.unflagged.Remove(s.unflaggedPos)
		s.unflaggedPos = nil
	}
}

func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max])
}

// joinCut joins items with commas, stopping before the list would pass
// labelMax characters.
func joinCut(items []string) string {
	var b strings.Builder
	for _, it := range items {
		extra := len(it)
		if b.Len() > 0 {
			extra++
		}
		if b.Len()+extra > labelMax {
			break
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(it)
	}
	return b.String()
}

// Flush closes the window: one web.probe per flagged address (the busiest
// maxProbeEventsPerCycle), the exposures seen since the last flush, and the
// cycle's counts. Everything else about the window is forgotten.
func (t *edgeTracker) Flush(now time.Time) (probes, exposures []spool.Event, stats edgeStats) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var flagged []*edgeSource
	for _, s := range t.sources {
		if s.flagged {
			flagged = append(flagged, s)
		}
	}
	sort.Slice(flagged, func(i, j int) bool {
		if flagged[i].requests != flagged[j].requests {
			return flagged[i].requests > flagged[j].requests
		}
		return flagged[i].ip < flagged[j].ip
	})
	stats = edgeStats{Lines: t.lines, Unparsed: t.unparsed, Flagged: len(flagged)}
	if len(flagged) > maxProbeEventsPerCycle {
		stats.Dropped = len(flagged) - maxProbeEventsPerCycle
		flagged = flagged[:maxProbeEventsPerCycle]
	}
	for _, s := range flagged {
		probes = append(probes, t.probeEvent(s, now))
	}
	exposures = t.exposures

	t.exposures = nil
	t.sources = map[string]*edgeSource{}
	t.unflagged.Init()
	t.lines, t.unparsed = 0, 0
	t.windowStart = now
	t.prune(now)
	return probes, exposures, stats
}

func (t *edgeTracker) prune(now time.Time) {
	window := serverActionLearnDays * 24 * time.Hour
	for _, a := range t.actions {
		for k, at := range a.Addresses {
			if now.Sub(at) > window {
				delete(a.Addresses, k)
			}
		}
	}
}

func (t *edgeTracker) probeEvent(s *edgeSource, now time.Time) spool.Event {
	var classes, words []string
	for i, c := range classOrder {
		if s.classes&(1<<i) != 0 {
			classes = append(classes, string(c))
			words = append(words, classWords[c])
		}
	}
	statuses := append([]statusCount(nil), s.statuses...)
	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].n != statuses[j].n {
			return statuses[i].n > statuses[j].n
		}
		return statuses[i].status < statuses[j].status
	})
	parts := make([]string, len(statuses))
	for i, st := range statuses {
		parts[i] = strconv.Itoa(st.status) + ":" + strconv.Itoa(st.n)
	}
	format := "json"
	if s.sawDefault {
		format = "default"
	}
	start := strconv.FormatInt(t.windowStart.Unix(), 10)

	title := fmt.Sprintf("%s probed the cluster (%s)", s.ip, strings.Join(words, ", "))
	if n := len(s.hosts); n > 0 {
		noun := "sites"
		if n == 1 {
			noun = "site"
		}
		title = fmt.Sprintf("%s probed %d %s (%s)", s.ip, n, noun, strings.Join(words, ", "))
	}
	return spool.Event{
		V:          1,
		Type:       "web.probe",
		Severity:   "info",
		Title:      truncateRunes(title, maxTitleRunes),
		OccurredAt: now.UTC().Format(time.RFC3339),
		DedupeKey:  "probe:" + s.ip + ":" + start,
		Labels: map[string]string{
			"source_ip":         s.ip,
			"requests":          strconv.Itoa(s.requests),
			"not_found":         strconv.Itoa(s.notFound),
			"hosts":             joinCut(s.hosts),
			"hosts_count":       strconv.Itoa(len(s.hosts)),
			"classes":           strings.Join(classes, ","),
			"paths":             joinCut(s.paths),
			"paths_total":       strconv.Itoa(len(s.pathHashes)),
			"statuses":          joinCut(parts),
			"crawler_claims":    joinCut(s.claims),
			"ua_count":          strconv.Itoa(len(s.agents)),
			"ua_sample":         s.agentSample,
			"format":            format,
			"signature_version": SignatureVersion,
			"window_start":      start,
		},
	}
}

func (t *edgeTracker) exposureEvent(l AccessLine, key, verdict string) spool.Event {
	size, typ, n := t.shapes[key].mode()
	notFoundType, notFoundBytes := "", ""
	if n >= shapeMinSamples {
		notFoundType, notFoundBytes = typ, strconv.FormatInt(size, 10)
	}
	// The default format records no Host header; the upstream is the best
	// name there is for where the file came from.
	host := l.Host
	if host == "" {
		host = l.Upstream
	}
	shown := l.ResponseType
	if shown == "" {
		shown = "unknown type"
	}
	format := "json"
	if !l.Full {
		format = "default"
	}
	dedupe := "exposure:" + l.RequestID
	if l.RequestID == "" {
		dedupe = fmt.Sprintf("exposure:%s:%d", l.IP, l.Time.UnixNano())
	}
	tail := fmt.Sprintf(" (%s, %d bytes) to %s", truncateRunes(shown, 60), l.Bytes, l.IP)
	head := truncateRunes(host, 80) + " sent "
	room := maxTitleRunes - utf8.RuneCountInString(head) - utf8.RuneCountInString(tail)
	path := l.Path
	if utf8.RuneCountInString(path) > room {
		path = truncateRunes(path, max(1, room-1)) + "…"
	}
	return spool.Event{
		V:          1,
		Type:       "web.exposure",
		Severity:   "info",
		Title:      head + path + tail,
		OccurredAt: l.Time.UTC().Format(time.RFC3339),
		DedupeKey:  truncateRunes(dedupe, 200),
		Labels: map[string]string{
			"source_ip":       l.IP,
			"host":            truncateRunes(host, labelMax),
			"path":            truncateRunes(l.Path, labelMax),
			"status":          strconv.Itoa(l.Status),
			"response_type":   truncateRunes(l.ResponseType, labelMax),
			"bytes":           strconv.FormatInt(l.Bytes, 10),
			"not_found_type":  truncateRunes(notFoundType, labelMax),
			"not_found_bytes": notFoundBytes,
			"verdict":         verdict,
			"format":          format,
		},
	}
}

type edgeState struct {
	V        int                        `json:"v"`
	Shapes   map[string]*notFoundShape  `json:"shapes,omitempty"`
	Learning map[string]*actionLearning `json:"server_actions,omitempty"`
}

func edgeStatePath(spoolDir string) string { return filepath.Join(spoolDir, "edge", "state.json") }

// Save writes what the tracker learned to <spoolDir>/edge/state.json.
func (t *edgeTracker) Save(spoolDir string) error {
	t.mu.Lock()
	data, err := json.Marshal(edgeState{V: edgeStateVersion, Shapes: t.shapes, Learning: t.actions})
	t.mu.Unlock()
	if err != nil {
		return err
	}
	path := edgeStatePath(spoolDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// loadEdgeTracker starts a tracker from a saved state, if there is a usable
// one. A missing file starts fresh; an unreadable one starts fresh and says so.
func loadEdgeTracker(spoolDir string, maxAddresses int, logger *slog.Logger) *edgeTracker {
	t := newEdgeTracker(maxAddresses)
	if spoolDir == "" {
		return t
	}
	data, err := os.ReadFile(edgeStatePath(spoolDir))
	if errors.Is(err, os.ErrNotExist) {
		return t
	}
	var st edgeState
	if err == nil {
		err = json.Unmarshal(data, &st)
	}
	if err == nil && st.V != edgeStateVersion {
		err = fmt.Errorf("unsupported version %d", st.V)
	}
	if err != nil {
		logger.Warn("kubernetes: ingress log state unreadable; learning starts over",
			"path", edgeStatePath(spoolDir), "error", err)
		return t
	}
	for k, s := range st.Shapes {
		if s != nil {
			t.shapes[k] = s
		}
	}
	for k, a := range st.Learning {
		if a != nil {
			t.actions[k] = a
		}
	}
	return t
}
