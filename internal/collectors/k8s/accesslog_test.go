package k8s

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func readLines(t testing.TB, name string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "accesslog", name))
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	return lines
}

func TestParseJSONLine(t *testing.T) {
	// Written by ingress-nginx with the JSON log format from iac (nginx -t and
	// a real request against it), user agent with quotes and a backslash.
	line := []byte(`{"time":"2026-10-24T00:28:59+00:00","ip":"203.0.113.10","method":"POST","host":"moriah.app","path":"/","protocol":"HTTP/1.1","status":"404","bytes":"22","request_bytes":"160","duration":"0.000","user_agent":"CCBot/2.0 \"quoted\" \\ back","content_type":"text/x-component","response_type":"text/html","next_action":"x","rsc":"1","namespace":"epistles","ingress":"api","service":"backend","upstream":"epistles-backend-3000","upstream_addr":"10.0.0.10:3000","upstream_status":"404","upstream_time":"0.000","request_id":"5bbc0f5ee601496720cea6759fd876cd"}`)
	l, ok := ParseAccessLine(line)
	if !ok {
		t.Fatal("not parsed")
	}
	want := AccessLine{
		Time:         time.Date(2026, 10, 24, 0, 28, 59, 0, time.UTC),
		IP:           "203.0.113.10",
		Method:       "POST",
		Host:         "moriah.app",
		Path:         "/",
		Protocol:     "HTTP/1.1",
		Status:       404,
		Bytes:        22,
		UserAgent:    `CCBot/2.0 "quoted" \ back`,
		ContentType:  "text/x-component",
		ResponseType: "text/html",
		NextAction:   "x",
		RSC:          "1",
		Namespace:    "epistles",
		Ingress:      "api",
		Upstream:     "epistles-backend-3000",
		RequestID:    "5bbc0f5ee601496720cea6759fd876cd",
		Full:         true,
	}
	if !l.Time.Equal(want.Time) {
		t.Errorf("time = %v, want %v", l.Time, want.Time)
	}
	l.Time = want.Time
	if l != want {
		t.Errorf("parsed\n %+v\nwant\n %+v", l, want)
	}
}

func TestParseEveryFixtureLine(t *testing.T) {
	for _, name := range []string{"json.log", "1023.log", "normal.log"} {
		for i, line := range readLines(t, name) {
			if _, ok := ParseAccessLine(line); !ok {
				t.Errorf("%s:%d not parsed", name, i+1)
			}
		}
	}
}

func TestParseDefaultLine(t *testing.T) {
	lines := readLines(t, "default.log")
	l, ok := ParseAccessLine(lines[0])
	if !ok {
		t.Fatal("not parsed")
	}
	if l.Path != "/verify" || l.Method != "GET" || l.Protocol != "HTTP/2.0" || l.Status != 404 || l.Bytes != 548 {
		t.Errorf("got %+v", l)
	}
	if l.IP != "203.0.113.7" || l.Upstream != "moriah-moriah-web-3000" || l.RequestID != "6f0c2b1e9d8a7c6b5a4f3e2d1c0b9a88" {
		t.Errorf("got %+v", l)
	}
	if l.UserAgent != "CCBot/2.0 (https://commoncrawl.org/faq/)" {
		t.Errorf("user agent %q", l.UserAgent)
	}
	if !l.Time.Equal(time.Date(2026, 10, 23, 14, 2, 11, 0, time.UTC)) {
		t.Errorf("time %v", l.Time)
	}
	if l.Full || l.Host != "" {
		t.Errorf("the default format knows no host or response type: %+v", l)
	}
	if strings.Contains(strings.ToUpper(strings.Join(fields(l), "|")), "SECRET") {
		t.Errorf("the query string or referrer leaked into %+v", l)
	}

	// Retries list several upstreams; the request id is still the last field.
	l, ok = ParseAccessLine(lines[1])
	if !ok || l.IP != "2001:db8::7" || l.Path != "/graphql" || l.RequestID != "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a" {
		t.Errorf("retried request: ok=%v %+v", ok, l)
	}
}

func fields(l AccessLine) []string {
	return []string{l.IP, l.Method, l.Host, l.Path, l.Protocol, l.UserAgent, l.ContentType, l.ResponseType,
		l.NextAction, l.RSC, l.Namespace, l.Ingress, l.Upstream, l.RequestID}
}

func TestParseTimestampPrefix(t *testing.T) {
	line := []byte(`2026-10-24T00:17:08.123456789Z {"time":"2026-10-24T00:17:07+00:00","ip":"203.0.113.10","method":"GET","host":"moriah.app","path":"/.env","protocol":"HTTP/1.1","status":"404","bytes":"22","user_agent":"curl/8.17.0","content_type":"","response_type":"text/html","next_action":"","rsc":"","request_id":"de2d09cc63ad8808cfa1f723bcd6cb25"}`)
	l, ok := ParseAccessLine(line)
	if !ok {
		t.Fatal("not parsed")
	}
	if !l.Time.Equal(time.Date(2026, 10, 24, 0, 17, 7, 0, time.UTC)) {
		t.Errorf("time %v: the request's own time wins over the log timestamp", l.Time)
	}
	if l.Path != "/.env" || !l.Full {
		t.Errorf("got %+v", l)
	}
}

func TestParseQueryStringNeverSurvives(t *testing.T) {
	// $uri carries no query string, but a format using $request_uri would.
	line := []byte(`{"time":"2026-10-24T00:17:07+00:00","ip":"203.0.113.10","method":"GET","host":"moriah.app","path":"/reset?token=SECRET#frag","protocol":"HTTP/1.1","status":"200","bytes":"22","user_agent":"x","content_type":"","response_type":"text/html","next_action":"","rsc":"","request_id":"de2d09cc63ad8808cfa1f723bcd6cb25"}`)
	l, ok := ParseAccessLine(line)
	if !ok || l.Path != "/reset" {
		t.Fatalf("ok=%v path=%q", ok, l.Path)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	long := append([]byte(`{"time":"2026-10-24T00:17:07+00:00","ip":"203.0.113.10","method":"GET","path":"/`), bytes.Repeat([]byte("a"), 64<<10)...)
	long = append(long, []byte(`","status":"200","bytes":"1"}`)...)
	for name, line := range map[string][]byte{
		"empty":           nil,
		"brace":           []byte("{"),
		"tls on http":     []byte("\x16\x03\x01\x02\x00"),
		"64 KiB":          long,
		"tls request":     readLines(t, "default.log")[2],
		"status words":    []byte(`{"time":"2026-10-24T00:17:07+00:00","ip":"203.0.113.10","method":"GET","path":"/","status":"ok","bytes":"1"}`),
		"bytes words":     []byte(`{"time":"2026-10-24T00:17:07+00:00","ip":"203.0.113.10","method":"GET","path":"/","status":"200","bytes":"lots"}`),
		"no address":      []byte(`{"time":"2026-10-24T00:17:07+00:00","ip":"","method":"GET","path":"/","status":"200","bytes":"1"}`),
		"not an address":  []byte(`{"time":"2026-10-24T00:17:07+00:00","ip":"moriah.app","method":"GET","path":"/","status":"200","bytes":"1"}`),
		"relative path":   []byte(`{"time":"2026-10-24T00:17:07+00:00","ip":"203.0.113.10","method":"GET","path":"etc/passwd","status":"200","bytes":"1"}`),
		"array":           []byte(`[1,2,3]`),
		"nginx error log": []byte(`2026/10/24 12:57:01 [warn] 165#165: *8483384 a client request body is buffered to a temporary file`),
	} {
		if _, ok := ParseAccessLine(line); ok {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestParseInvalidUTF8(t *testing.T) {
	line := []byte("{\"time\":\"2026-10-24T00:17:07+00:00\",\"ip\":\"203.0.113.10\",\"method\":\"GET\",\"host\":\"moriah.app\",\"path\":\"/\xff\xfe.env\",\"protocol\":\"HTTP/1.1\",\"status\":\"404\",\"bytes\":\"1\",\"user_agent\":\"\xc3\x28\",\"content_type\":\"\",\"response_type\":\"\",\"next_action\":\"\",\"rsc\":\"\",\"request_id\":\"r\"}")
	l, ok := ParseAccessLine(line)
	if !ok {
		t.Fatal("not parsed")
	}
	for _, f := range fields(l) {
		if !utf8.ValidString(f) {
			t.Errorf("invalid UTF-8 kept: %q", f)
		}
	}
}

func TestControllerMessages(t *testing.T) {
	for _, line := range []string{
		`2026/10/24 12:57:01 [warn] 165#165: *8483384 a client request body is buffered to a temporary file /tmp/nginx/client-body/0000000001`,
		`W1024 12:57:02.933435       8 controller.go:575] Service "shop/web" does not have any active Endpoint`,
		`I1024 12:57:03.959718       8 admission.go:149] processed ingress via admission controller`,
		`2026-10-24T12:57:01.000000001Z 2026/10/24 12:57:01 [error] 33#33: *1 upstream timed out`,
	} {
		if !IsControllerMessage([]byte(line)) {
			t.Errorf("not recognized: %s", line)
		}
	}
	for _, line := range readLines(t, "1023.log") {
		if IsControllerMessage(line) {
			t.Errorf("an access line taken for a controller message: %s", line)
		}
	}
}

func FuzzParseAccessLine(f *testing.F) {
	for _, name := range []string{"json.log", "default.log", "1023.log"} {
		for _, line := range readLines(f, name) {
			f.Add(line)
		}
	}
	f.Add([]byte("\x16\x03\x01"))
	f.Fuzz(func(t *testing.T, line []byte) {
		l, ok := ParseAccessLine(line)
		if !ok {
			return
		}
		if strings.ContainsAny(l.Path, "?#") || !strings.HasPrefix(l.Path, "/") {
			t.Errorf("path %q", l.Path)
		}
		if l.Status < 100 || l.Status > 599 || l.Bytes < 0 {
			t.Errorf("status %d bytes %d", l.Status, l.Bytes)
		}
		for _, field := range fields(l) {
			if !utf8.ValidString(field) || len(field) > maxAccessLine {
				t.Errorf("field %q", field)
			}
		}
	})
}
