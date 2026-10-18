package k8s

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

/*
A minimal Prometheus text-format reader.

Only what is needed to lift a handful of named series out of an exporter's
/metrics: sample lines of the form

    name{label="value",...} 12.34 [timestamp]

Comment lines are skipped. Histogram and summary suffixes and exemplars are not
in any caller's wanted set, so they need no special handling.
*/

type promSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// parsePromText reads samples whose name is in `want`. Anything else is skipped
// without allocating, because an exporter emits thousands of lines and only a
// dozen are needed. A read error, including a line too long to buffer, fails
// the whole page: a partial page would look like a complete one with series
// missing.
func parsePromText(r io.Reader, want map[string]bool) ([]promSample, error) {
	var out []promSample
	sc := bufio.NewScanner(r)
	// A series with many labels can exceed the default 64KiB token.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		name, labelPart, rest, ok := splitPromLine(line)
		if !ok || !want[name] {
			continue
		}
		// The value is followed by an optional timestamp and, in OpenMetrics,
		// an optional exemplar. Only the value is used.
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		out = append(out, promSample{Name: name, Labels: parsePromLabels(labelPart), Value: v})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// splitPromLine separates a sample line into its metric name, the text inside
// its braces (if any) and everything after the identifier. The closing brace is
// found by walking the quoted label values, because a value may legally
// contain spaces, braces and escaped quotes.
func splitPromLine(line string) (name, labels, rest string, ok bool) {
	i := strings.IndexAny(line, "{ \t")
	if i <= 0 {
		return "", "", "", false
	}
	name = line[:i]
	if line[i] != '{' {
		return name, "", line[i:], true
	}
	inQuote := false
	for j := i + 1; j < len(line); j++ {
		switch {
		case inQuote && line[j] == '\\':
			j++ // skip the escaped character
		case line[j] == '"':
			inQuote = !inQuote
		case !inQuote && line[j] == '}':
			return name, line[i+1 : j], line[j+1:], true
		}
	}
	return "", "", "", false
}

// parsePromLabels reads `a="1",b="2"`, honoring escaped quotes.
func parsePromLabels(s string) map[string]string {
	labels := map[string]string{}
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(s[:eq])
		rest := s[eq+1:]
		if len(rest) == 0 || rest[0] != '"' {
			break
		}

		// Walk to the closing quote, skipping \" and \\.
		i := 1
		var val strings.Builder
		for i < len(rest) {
			if rest[i] == '\\' && i+1 < len(rest) {
				switch rest[i+1] {
				case '"', '\\':
					val.WriteByte(rest[i+1])
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(rest[i+1])
				}
				i += 2
				continue
			}
			if rest[i] == '"' {
				break
			}
			val.WriteByte(rest[i])
			i++
		}
		if i >= len(rest) {
			break
		}
		labels[key] = val.String()

		s = strings.TrimPrefix(strings.TrimSpace(rest[i+1:]), ",")
	}
	return labels
}
