package security

import (
	"encoding/json"
	"testing"

	"netwarden/internal/metrics"
)

func TestBuildSSHConfigSnapshot_PortIsNumeric(t *testing.T) {
	// The agent parses Port out of a text config file, but the server
	// contract declares `port?: number`. Sending the string would fail Zod
	// validation and take the whole request with it.
	snap := buildSSHConfigSnapshot(sshConfigFindings{Port: "2222"})

	raw, err := json.Marshal(snap.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	port, ok := decoded["port"].(float64) // JSON numbers decode as float64
	if !ok {
		t.Fatalf("port encoded as %T, want a JSON number: %s", decoded["port"], raw)
	}
	if port != 2222 {
		t.Errorf("port = %v, want 2222", port)
	}
}

func TestBuildSSHConfigSnapshot_OmitsUnparseablePort(t *testing.T) {
	for _, bad := range []string{"", "ssh", "0", "70000", "-1", "22 # comment"} {
		snap := buildSSHConfigSnapshot(sshConfigFindings{Port: bad})
		if v, present := snap.Payload["port"]; present {
			t.Errorf("Port=%q produced port=%v; an out-of-range or unparseable "+
				"value must be omitted, not guessed", bad, v)
		}
	}
}

func TestBuildSSHConfigSnapshot_BooleansAlwaysPresent(t *testing.T) {
	// These five are non-optional in SshConfigSnapshot; omitting any of them
	// fails server-side validation even though Go's zero value is valid.
	snap := buildSSHConfigSnapshot(sshConfigFindings{})
	for _, key := range []string{
		"permit_root_login", "password_auth", "protocol_v1",
		"x11_forwarding", "empty_passwords",
	} {
		v, present := snap.Payload[key]
		if !present {
			t.Errorf("required field %q missing from payload", key)
			continue
		}
		if _, ok := v.(bool); !ok {
			t.Errorf("field %q is %T, want bool", key, v)
		}
	}
}

func TestBuildSSHConfigSnapshot_Type(t *testing.T) {
	if got := buildSSHConfigSnapshot(sshConfigFindings{}).Type; got != metrics.SnapshotSSHConfig {
		t.Errorf("snapshot type = %q, want %q", got, metrics.SnapshotSSHConfig)
	}
}

func TestSplitAlgoList(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"empty means absent", "", nil},
		{"single", "aes256-gcm@openssh.com", []string{"aes256-gcm@openssh.com"}},
		{
			"comma separated",
			"aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
			[]string{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"},
		},
		{"whitespace trimmed", " aes256-ctr , aes192-ctr ", []string{"aes256-ctr", "aes192-ctr"}},
		{"empty entries dropped", "aes256-ctr,,aes192-ctr", []string{"aes256-ctr", "aes192-ctr"}},
		{"only separators means absent", ",,,", nil},
		// sshd's +/-/^ prefixes modify the built-in default set rather than
		// replacing it. The prefix changes the meaning, so it must survive.
		{"append prefix preserved", "+diffie-hellman-group14-sha1", []string{"+diffie-hellman-group14-sha1"}},
		{"remove prefix preserved", "-hmac-md5", []string{"-hmac-md5"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := splitAlgoList(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("splitAlgoList(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("splitAlgoList(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestBuildSSHConfigSnapshot_AlgoListsOmittedWhenAbsent(t *testing.T) {
	// Absent directives must be omitted, not sent as [] — an empty array
	// would read as "this host negotiates no ciphers at all".
	snap := buildSSHConfigSnapshot(sshConfigFindings{Port: "22"})
	for _, key := range []string{"kex_algorithms", "ciphers", "macs"} {
		if v, present := snap.Payload[key]; present {
			t.Errorf("%q present as %v when the directive was absent", key, v)
		}
	}
}
