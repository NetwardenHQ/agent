package security

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func winFixture(t *testing.T, name string) winRecord {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "win", name))
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseWinEventXML(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func noSID(string) string { return "" }

func TestWinParseRecord(t *testing.T) {
	r := winFixture(t, "4624-rdp.xml")
	want := time.Date(2026, 10, 23, 12, 0, 0, 123456700, time.UTC)
	if r.EventID != 4624 || r.RecordID != 1001 || !r.Time.Equal(want) || r.Data["LogonType"] != "10" || r.Data["IpAddress"] != "203.0.113.7" {
		t.Fatalf("%+v", r)
	}
	if _, err := parseWinEventXML([]byte("<Event><System>")); err == nil {
		t.Fatal("truncated XML parsed")
	}
}

func TestWinClassifyLogons(t *testing.T) {
	cases := []struct {
		file, typ, user, ip, auth string
	}{
		{"4624-rdp.xml", "rdp.login", `CORP\Alice`, "203.0.113.7", ""},
		{"4624-network-public.xml", "network.login", `PC-7\alice`, "203.0.113.9", "NTLM"},
		{"4624-console.xml", "console.login", `PC-7\alice`, "", ""},
	}
	for _, c := range cases {
		o, ok := classifyWinRecord(winFixture(t, c.file), noSID)
		if !ok || o.Event == nil || o.Failure {
			t.Fatalf("%s: %+v %v", c.file, o, ok)
		}
		e := o.Event
		if e.Type != c.typ || e.User != c.user || e.SourceIP != c.ip || e.Auth != c.auth || e.Key != "win:"+strconv.FormatUint(winFixture(t, c.file).RecordID, 10) {
			t.Errorf("%s: %+v", c.file, e)
		}
	}
}

func TestWinSkipsNoise(t *testing.T) {
	for _, f := range []string{"4624-network-lan.xml", "4624-dwm.xml", "4732-users.xml"} {
		if o, ok := classifyWinRecord(winFixture(t, f), noSID); ok {
			t.Errorf("%s produced %+v", f, o)
		}
	}
}

func TestWinFailureIsACountNotAnEvent(t *testing.T) {
	o, ok := classifyWinRecord(winFixture(t, "4625.xml"), noSID)
	if !ok || !o.Failure || o.Event != nil || o.FailedIP != "203.0.113.66" {
		t.Fatalf("%+v %v", o, ok)
	}
}

func TestWinAccountChanges(t *testing.T) {
	o, ok := classifyWinRecord(winFixture(t, "4720.xml"), noSID)
	if !ok || o.Event == nil || o.Event.Type != "account.created" || o.Event.User != `PC-7\bob` || o.Event.By != `PC-7\alice` {
		t.Fatalf("4720: %+v %v", o, ok)
	}
	resolve := func(sid string) string {
		if sid == "S-1-5-21-1-2-3-1009" {
			return `PC-7\bob`
		}
		return ""
	}
	o, ok = classifyWinRecord(winFixture(t, "4732-admins.xml"), resolve)
	if !ok || o.Event == nil || o.Event.Type != "account.admin_granted" || o.Event.User != `PC-7\bob` ||
		o.Event.Group != "Administrators" || o.Event.By != `PC-7\alice` {
		t.Fatalf("4732: %+v %v", o, ok)
	}
	// Without a name for the SID, the SID itself identifies the account.
	o, _ = classifyWinRecord(winFixture(t, "4732-admins.xml"), noSID)
	if o.Event == nil || o.Event.User != "S-1-5-21-1-2-3-1009" {
		t.Fatalf("4732 unresolved: %+v", o)
	}
}

func TestWinLogCleared(t *testing.T) {
	o, ok := classifyWinRecord(winFixture(t, "1102.xml"), noSID)
	if !ok || o.Event == nil || o.Event.Type != "audit.log_cleared" || o.Event.By != `PC-7\Administrator` || o.Event.Key != "win:1010" {
		t.Fatalf("%+v %v", o, ok)
	}
}

// The agent sends the account as Windows names it; folding case and domain
// for matching is the platform's job.
func TestUserCaseKept(t *testing.T) {
	o, _ := classifyWinRecord(winFixture(t, "4624-rdp.xml"), noSID)
	if o.Event == nil || o.Event.User != `CORP\Alice` {
		t.Fatalf("%+v", o)
	}
}
