package k8s

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

/*
Parsing the ingress-nginx access log.

Two formats are understood:

  - The JSON format the controller's ConfigMap sets with log-format-upstream
    and log-format-escape-json (one object per line, every value a string).
    It carries the Host header, the response type and the Next.js
    server-action headers, which is what makes a line Full.
  - The controller's default format. It has no host and no response type, so
    anything that depends on them (server actions, the exposure verdict) is
    out of reach; the rest still classifies.

Lines read through the API with timestamps=true start with the kubelet's
RFC 3339 timestamp. It is stripped, and used only when the line has no time
of its own.

The query string is cut from the path before anything else looks at it:
tokens and reset links live there, and nothing downstream may see them. The
referrer is never kept for the same reason. A line that is too long, is not
valid in either format, or has a number that does not parse is rejected
whole; nothing is guessed or defaulted to zero.
*/

// maxAccessLine bounds a line we are willing to parse. Real lines are well
// under 4 KiB; anything far larger is a flood or a broken controller.
const maxAccessLine = 16 << 10

// AccessLine is one request from the access log.
type AccessLine struct {
	Time         time.Time
	IP           string
	Method       string
	Host         string
	Path         string
	Protocol     string
	Status       int
	Bytes        int64
	UserAgent    string
	ContentType  string
	ResponseType string
	NextAction   string
	RSC          string
	Namespace    string
	Ingress      string
	Upstream     string
	RequestID    string
	// Full is true for the JSON format, where Host, ResponseType, NextAction,
	// RSC and ContentType are known. The default format leaves them empty.
	Full bool
}

// accessJSON mirrors the JSON log format. Pointers tell a missing key from an
// empty value: an empty next_action means "no header", a missing one means the
// format does not record it.
type accessJSON struct {
	Time         *string `json:"time"`
	IP           *string `json:"ip"`
	Method       *string `json:"method"`
	Host         *string `json:"host"`
	Path         *string `json:"path"`
	Protocol     *string `json:"protocol"`
	Status       *string `json:"status"`
	Bytes        *string `json:"bytes"`
	UserAgent    *string `json:"user_agent"`
	ContentType  *string `json:"content_type"`
	ResponseType *string `json:"response_type"`
	NextAction   *string `json:"next_action"`
	RSC          *string `json:"rsc"`
	Namespace    *string `json:"namespace"`
	Ingress      *string `json:"ingress"`
	Upstream     *string `json:"upstream"`
	RequestID    *string `json:"request_id"`
}

// The controller's default log-format-upstream:
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//	"$http_referer" "$http_user_agent" $request_length $request_time
//	[$proxy_upstream_name] [$proxy_alternative_upstream_name] $upstream_addr
//	$upstream_response_length $upstream_response_time $upstream_status $req_id
//
// The upstream fields become comma lists when nginx retried, so only the
// fixed head and the trailing request id are matched exactly. nginx escapes
// quotes inside the quoted fields, so [^"]* cannot run past one.
var defaultAccessLine = regexp.MustCompile(
	`^(\S+) - \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "[^"]*" "([^"]*)" \S+ \S+ \[([^\]]*)\] \[[^\]]*\] .* ([0-9a-f]{32})$`)

const timeLocalLayout = "02/Jan/2006:15:04:05 -0700"

var methodToken = regexp.MustCompile(`^[A-Za-z]{1,16}$`)

// ParseAccessLine parses one access log line in either format.
func ParseAccessLine(line []byte) (AccessLine, bool) {
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 || len(line) > maxAccessLine {
		return AccessLine{}, false
	}
	logged, line := splitLogTimestamp(line)
	var l AccessLine
	var ok bool
	if line[0] == '{' {
		l, ok = parseJSONAccess(line)
	} else {
		l, ok = parseDefaultAccess(line)
	}
	if !ok {
		return AccessLine{}, false
	}
	if l.Time.IsZero() {
		if logged.IsZero() {
			return AccessLine{}, false
		}
		l.Time = logged
	}
	return l, true
}

// IsControllerMessage reports lines the controller writes to the same stream
// that are not requests: nginx's error log and the controller's own klog
// output. They are skipped, not counted as unparsed.
func IsControllerMessage(line []byte) bool {
	_, line = splitLogTimestamp(bytes.TrimRight(line, "\r\n"))
	return nginxErrorLine.Match(line) || klogLine.Match(line)
}

var (
	nginxErrorLine = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[[a-z]+\] `)
	klogLine       = regexp.MustCompile(`^[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d+ +\d+ `)
)

// splitLogTimestamp removes the kubelet's "2026-10-24T00:17:08.123456789Z "
// prefix, if present.
func splitLogTimestamp(line []byte) (time.Time, []byte) {
	if len(line) < 21 || line[0] < '0' || line[0] > '9' {
		return time.Time{}, line
	}
	end := bytes.IndexByte(line[:min(len(line), 40)], ' ')
	if end < 0 {
		return time.Time{}, line
	}
	t, err := time.Parse(time.RFC3339Nano, string(line[:end]))
	if err != nil {
		return time.Time{}, line
	}
	rest := line[end+1:]
	if len(rest) == 0 {
		return time.Time{}, line
	}
	return t, rest
}

func parseJSONAccess(line []byte) (AccessLine, bool) {
	var j accessJSON
	if err := json.Unmarshal(line, &j); err != nil {
		return AccessLine{}, false
	}
	if j.IP == nil || j.Method == nil || j.Path == nil || j.Status == nil || j.Bytes == nil {
		return AccessLine{}, false
	}
	l := AccessLine{
		Host:         value(j.Host),
		Protocol:     value(j.Protocol),
		UserAgent:    value(j.UserAgent),
		ContentType:  value(j.ContentType),
		ResponseType: value(j.ResponseType),
		NextAction:   value(j.NextAction),
		RSC:          value(j.RSC),
		Namespace:    value(j.Namespace),
		Ingress:      value(j.Ingress),
		Upstream:     value(j.Upstream),
		RequestID:    value(j.RequestID),
		Full:         j.Host != nil && j.ResponseType != nil && j.NextAction != nil && j.RSC != nil && j.ContentType != nil,
	}
	if j.Time != nil {
		t, err := time.Parse(time.RFC3339, *j.Time)
		if err != nil {
			return AccessLine{}, false
		}
		l.Time = t
	}
	var ok bool
	if l.IP, ok = clientAddress(*j.IP); !ok {
		return AccessLine{}, false
	}
	if l.Method, ok = method(*j.Method); !ok {
		return AccessLine{}, false
	}
	if l.Path, ok = requestPath(*j.Path); !ok {
		return AccessLine{}, false
	}
	if l.Status, l.Bytes, ok = statusAndBytes(*j.Status, *j.Bytes); !ok {
		return AccessLine{}, false
	}
	return l, true
}

func parseDefaultAccess(line []byte) (AccessLine, bool) {
	m := defaultAccessLine.FindSubmatch(line)
	if m == nil {
		return AccessLine{}, false
	}
	// "$request" is "METHOD URI PROTOCOL". Anything else (a TLS handshake sent
	// to the plain-HTTP port, a bare garbage line) is not a request.
	parts := strings.Split(string(m[3]), " ")
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return AccessLine{}, false
	}
	t, err := time.Parse(timeLocalLayout, string(m[2]))
	if err != nil {
		return AccessLine{}, false
	}
	l := AccessLine{
		Time:      t,
		Protocol:  clean(parts[2]),
		UserAgent: clean(string(m[6])),
		Upstream:  clean(string(m[7])),
		RequestID: string(m[8]),
	}
	var ok bool
	if l.IP, ok = clientAddress(string(m[1])); !ok {
		return AccessLine{}, false
	}
	if l.Method, ok = method(parts[0]); !ok {
		return AccessLine{}, false
	}
	if l.Path, ok = requestPath(parts[1]); !ok {
		return AccessLine{}, false
	}
	if l.Status, l.Bytes, ok = statusAndBytes(string(m[4]), string(m[5])); !ok {
		return AccessLine{}, false
	}
	return l, true
}

func value(s *string) string {
	if s == nil {
		return ""
	}
	return clean(*s)
}

// clean makes a field safe to keep: valid UTF-8, no control characters.
func clean(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func clientAddress(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return a.Unmap().WithZone("").String(), true
}

func method(s string) (string, bool) {
	if !methodToken.MatchString(s) {
		return "", false
	}
	return strings.ToUpper(s), true
}

// requestPath cuts the query string and fragment, then insists on an
// origin-form path: an absolute URL or "*" is not a site's own path.
func requestPath(s string) (string, bool) {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if !strings.HasPrefix(s, "/") {
		return "", false
	}
	return clean(s), true
}

func statusAndBytes(status, size string) (int, int64, bool) {
	st, err := strconv.Atoi(status)
	if err != nil || st < 100 || st > 599 {
		return 0, 0, false
	}
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 0 {
		return 0, 0, false
	}
	return st, n, true
}
