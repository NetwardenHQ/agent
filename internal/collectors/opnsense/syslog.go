package opnsense

import (
	"bytes"
	"regexp"
)

// bsdHeaderRe matches the RFC 3164 header some older OPNsense releases and
// plugins still write: "<pri>Mmm dd hh:mm:ss host app[pid]: msg".
var bsdHeaderRe = regexp.MustCompile(`^<\d{1,3}>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ ([^\s\[:]+)(?:\[\d+\])?: `)

// splitSyslog returns the program name and the message of one syslog line.
// OPNsense writes RFC 5424:
//
//	<pri>1 timestamp host app procid msgid structured-data msg
//
// Lines are routed on the program field, never on substrings of the line: the
// message carries attacker-chosen text (an SSH username, a GUI login name), and
// a line must not be classified by what an attacker typed into it.
func splitSyslog(line []byte) (app, msg []byte, ok bool) {
	if m := bsdHeaderRe.FindSubmatchIndex(line); m != nil {
		return line[m[2]:m[3]], line[m[1]:], true
	}
	if len(line) == 0 || line[0] != '<' {
		return nil, nil, false
	}
	// Six space-separated header fields: <pri>version, timestamp, host, app,
	// procid, msgid. Then the structured data.
	rest := line
	var fields [6][]byte
	for i := range fields {
		sp := bytes.IndexByte(rest, ' ')
		if sp < 0 {
			return nil, nil, false
		}
		fields[i], rest = rest[:sp], rest[sp+1:]
	}
	if !bytes.HasSuffix(fields[0], []byte(">1")) {
		return nil, nil, false
	}
	sdEnd, ok := structuredDataEnd(rest)
	if !ok {
		return nil, nil, false
	}
	msg = rest[sdEnd:]
	if len(msg) > 0 && msg[0] == ' ' {
		msg = msg[1:]
	}
	return fields[3], msg, true
}

// structuredDataEnd returns the length of the RFC 5424 structured data at the
// start of b: "-" for none, otherwise one or more [id k="v" ...] elements.
// Inside a quoted value, '\' escapes '"', ']' and '\'.
func structuredDataEnd(b []byte) (int, bool) {
	if len(b) > 0 && b[0] == '-' {
		return 1, true
	}
	i := 0
	for i < len(b) && b[i] == '[' {
		inQuote := false
		for i++; i < len(b); i++ {
			c := b[i]
			if inQuote {
				switch c {
				case '\\':
					i++
				case '"':
					inQuote = false
				}
				continue
			}
			if c == '"' {
				inQuote = true
			} else if c == ']' {
				break
			}
		}
		if i >= len(b) {
			return 0, false
		}
		i++ // past ']'
	}
	return i, i > 0
}
