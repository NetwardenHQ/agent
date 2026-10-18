package postgresql

import (
	"strings"
	"testing"

	"github.com/NetwardenHQ/agent/internal/config"
)

// parseKV is a minimal libpq key/value reader (quoted values with backslash
// escapes), enough to check that buildConnStr's output round-trips.
func parseKV(t *testing.T, s string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for i := 0; i < len(s); {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			break
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			t.Fatalf("no '=' in %q", s[i:])
		}
		key := s[i : i+eq]
		i += eq + 1
		var val strings.Builder
		if i < len(s) && s[i] == '\'' {
			i++
			for ; i < len(s) && s[i] != '\''; i++ {
				if s[i] == '\\' {
					i++
				}
				val.WriteByte(s[i])
			}
			i++
		} else {
			for ; i < len(s) && s[i] != ' '; i++ {
				val.WriteByte(s[i])
			}
		}
		out[key] = val.String()
	}
	return out
}

// A password with spaces, quotes or "key=value" text must stay one value
// rather than rewrite the connection options.
func TestBuildConnStr_QuotesValues(t *testing.T) {
	c := &Collector{config: config.DatabaseConfig{
		PostgreSQLUser:     "mon",
		PostgreSQLPassword: `p a'ss\ host=evil`,
		PostgreSQLHost:     "db.internal:6543",
	}}
	kv := parseKV(t, c.buildConnStr())
	if kv["password"] != `p a'ss\ host=evil` || kv["host"] != "db.internal" || kv["port"] != "6543" {
		t.Fatalf("parsed back as %v", kv)
	}
}

// Local connections keep sslmode=disable; a remote host prefers TLS.
func TestBuildConnStr_SSLMode(t *testing.T) {
	cases := []struct {
		cfg  config.DatabaseConfig
		want string
	}{
		{config.DatabaseConfig{PostgreSQLUser: "u"}, "disable"},
		{config.DatabaseConfig{PostgreSQLUser: "u", PostgreSQLHost: "127.0.0.1"}, "disable"},
		{config.DatabaseConfig{PostgreSQLUser: "u", PostgreSQLHost: "[::1]:5433"}, "disable"},
		{config.DatabaseConfig{PostgreSQLUser: "u", PostgreSQLSocket: "/var/run/postgresql"}, "disable"},
		{config.DatabaseConfig{PostgreSQLUser: "u", PostgreSQLHost: "db.internal"}, "prefer"},
		{config.DatabaseConfig{PostgreSQLHost: "10.0.0.5:5432"}, "prefer"},
	}
	for _, tc := range cases {
		c := &Collector{config: tc.cfg}
		if got := parseKV(t, c.buildConnStr())["sslmode"]; got != tc.want {
			t.Errorf("%+v: sslmode = %q, want %q", tc.cfg, got, tc.want)
		}
	}
}
