package agentid

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadCreatesTheIDOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "agent-id")

	first, err := Load(path)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if !Valid(first) {
		t.Fatalf("Load returned %q, which is not a valid id", first)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the id was not written: %v", err)
	}
	if got := strings.TrimSpace(string(raw)); got != first {
		t.Fatalf("file holds %q, Load returned %q", got, first)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("id file mode = %o, want 600", perm)
		}
	}

	second, err := Load(path)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if second != first {
		t.Fatalf("id changed between starts: %q then %q", first, second)
	}
}

func TestLoadGeneratesDistinctIDs(t *testing.T) {
	dir := t.TempDir()
	a, err := Load(filepath.Join(dir, "a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(filepath.Join(dir, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two installations got the same id %q", a)
	}
}

// An installer rewrites netwarden.conf; on Synology the id lives in the same
// folder. The id must not depend on anything in the config file.
func TestIDSurvivesAConfigRewrite(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "netwarden.conf")
	if err := os.WriteFile(conf, []byte("api_key: nw_sk_first\nhostname: one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := Path(Env{GOOS: "linux", ConfigFile: conf, DSM: true})
	if filepath.Dir(path) != dir || path == conf {
		t.Fatalf("Path = %q, want a file of its own in %q", path, dir)
	}

	before, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("api_key: nw_sk_second\nhostname: two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("id changed with the config: %q then %q", before, after)
	}
}

func TestLoadAcceptsAHandWrittenID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-id")
	if err := os.WriteFile(path, []byte("  0B8F6C1E-5D0A-4A52-9A44-3F1C2E7D9A10\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "0b8f6c1e-5d0a-4a52-9a44-3f1c2e7d9a10"; got != want {
		t.Fatalf("Load = %q, want %q", got, want)
	}
}

// A file that is there but holds no id (truncated, edited) cannot be
// recovered: the id it held is gone either way, so a new one replaces it.
func TestLoadReplacesAFileThatHoldsNoID(t *testing.T) {
	for name, content := range map[string]string{
		"empty":     "",
		"truncated": "0b8f6c1e-5d0a-4a52",
		"garbage":   "not an id\n",
		"two lines": "0b8f6c1e-5d0a-4a52-9a44-3f1c2e7d9a10\n7e2d9c40-1b3f-4c68-8d17-a5b4c3d2e1f0\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent-id")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			id, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !Valid(id) {
				t.Fatalf("Load returned %q", id)
			}
			again, err := Load(path)
			if err != nil || again != id {
				t.Fatalf("replacement was not kept: %q, %v (want %q)", again, err, id)
			}
		})
	}
}

// A file that cannot be read may hold a good id. Replacing it would turn this
// host into a new one, so Load reports the error and returns no id.
func TestLoadDoesNotReplaceWhatItCannotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-id")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := Load(path)
	if err == nil || id != "" {
		t.Fatalf("Load = %q, %v; want no id and an error", id, err)
	}
	if fi, statErr := os.Stat(path); statErr != nil || !fi.IsDir() {
		t.Fatalf("the unreadable path was replaced")
	}
}

// Where the id cannot be stored there is none: an id that lasted only until
// the next start would make every start a new host.
func TestLoadReturnsNoIDItCouldNotStore(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "state")
	if err := os.WriteFile(blocker, []byte("a file where the directory should be"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := Load(filepath.Join(blocker, "agent-id"))
	if err == nil || id != "" {
		t.Fatalf("Load = %q, %v; want no id and an error", id, err)
	}
}

func TestLoadWithNoPath(t *testing.T) {
	id, err := Load("")
	if err == nil || id != "" {
		t.Fatalf("Load(\"\") = %q, %v; want no id and an error", id, err)
	}
}

func TestPath(t *testing.T) {
	cases := []struct {
		name string
		env  Env
		want string
	}{
		{"linux", Env{GOOS: "linux", ConfigFile: "/etc/netwarden/netwarden.conf"}, "/var/lib/netwarden/agent-id"},
		{"macOS", Env{GOOS: "darwin", ConfigFile: "/etc/netwarden/netwarden.conf"}, "/var/lib/netwarden/agent-id"},
		{"FreeBSD", Env{GOOS: "freebsd", ConfigFile: "/usr/local/etc/netwarden/netwarden.conf"}, "/var/db/netwarden/agent-id"},
		{"Windows", Env{GOOS: "windows", ProgramData: `D:\ProgramData`}, filepath.Join(`D:\ProgramData`, "Netwarden", "agent-id")},
		{"Windows without ProgramData", Env{GOOS: "windows"}, filepath.Join(`C:\ProgramData`, "Netwarden", "agent-id")},
		{"Synology", Env{GOOS: "linux", DSM: true, ConfigFile: "/volume1/@appdata/netwarden/netwarden.conf"}, "/volume1/@appdata/netwarden/agent-id"},
		{"Synology without a config path", Env{GOOS: "linux", DSM: true}, ""},
		{"Kubernetes", Env{GOOS: "linux", Kubernetes: true, ConfigFile: "/etc/netwarden/netwarden.conf"}, ""},
		{"other", Env{GOOS: "plan9"}, ""},
	}
	for _, c := range cases {
		if got := Path(c.env); got != c.want {
			t.Errorf("%s: Path = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestValid(t *testing.T) {
	for id, want := range map[string]bool{
		"0b8f6c1e-5d0a-4a52-9a44-3f1c2e7d9a10":  true,
		"0B8F6C1E-5D0A-4A52-9A44-3F1C2E7D9A10":  false,
		"0b8f6c1e5d0a4a529a443f1c2e7d9a10":      false,
		"0b8f6c1e-5d0a-4a52-9a44-3f1c2e7d9a1":   false,
		"0b8f6c1e-5d0a-4a52-9a44-3f1c2e7d9a10 ": false,
		"zb8f6c1e-5d0a-4a52-9a44-3f1c2e7d9a10":  false,
		"":                                      false,
	} {
		if got := Valid(id); got != want {
			t.Errorf("Valid(%q) = %v, want %v", id, got, want)
		}
	}
}
