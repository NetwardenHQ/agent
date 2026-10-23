package security

import (
	"encoding/xml"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Reading Windows Security log events, as rendered XML (EvtRender with
// EvtRenderEventXml), into the same security events and failed-login counts
// the Linux collector produces. Platform-neutral so it is tested anywhere;
// auth_windows.go and winlog_windows.go do the reading.
//
//	4624  an account logged on      console (types 2, 11), Remote Desktop (10),
//	                                network (3, only from a public address)
//	4625  an account failed to log on   counted, never sent as an event
//	4720  a user account was created
//	4732  a member was added to a local group   only Administrators (S-1-5-32-544)
//	1102  the audit log was cleared

// winSecurityQuery selects the events above from the Security channel.
const winSecurityQuery = "*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4732 or EventID=1102)]]"

const administratorsSID = "S-1-5-32-544"

// winRecord is the part of a rendered event the classifier reads.
type winRecord struct {
	EventID  int
	RecordID uint64
	Time     time.Time
	Data     map[string]string // EventData/Data by Name, and LogFileCleared's fields for 1102
}

type xmlWinEvent struct {
	System struct {
		EventID       string `xml:"EventID"`
		EventRecordID string `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		LogFileCleared struct {
			SubjectUserName   string `xml:"SubjectUserName"`
			SubjectDomainName string `xml:"SubjectDomainName"`
		} `xml:"LogFileCleared"`
	} `xml:"UserData"`
}

func parseWinEventXML(b []byte) (winRecord, error) {
	var x xmlWinEvent
	if err := xml.Unmarshal(b, &x); err != nil {
		return winRecord{}, err
	}
	id, err := strconv.Atoi(strings.TrimSpace(x.System.EventID))
	if err != nil {
		return winRecord{}, fmt.Errorf("event id %q: %w", x.System.EventID, err)
	}
	rec, err := strconv.ParseUint(strings.TrimSpace(x.System.EventRecordID), 10, 64)
	if err != nil {
		return winRecord{}, fmt.Errorf("record id %q: %w", x.System.EventRecordID, err)
	}
	at, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime)
	if err != nil {
		return winRecord{}, fmt.Errorf("time %q: %w", x.System.TimeCreated.SystemTime, err)
	}
	data := make(map[string]string, len(x.EventData.Data)+2)
	for _, d := range x.EventData.Data {
		data[d.Name] = strings.TrimSpace(d.Value)
	}
	if lc := x.UserData.LogFileCleared; lc.SubjectUserName != "" {
		data["SubjectUserName"] = lc.SubjectUserName
		data["SubjectDomainName"] = lc.SubjectDomainName
	}
	return winRecord{EventID: id, RecordID: rec, Time: at.UTC(), Data: data}, nil
}

// winOutcome is what one record means: a security event, or a failed logon
// to count (its account name is counted, never sent).
type winOutcome struct {
	Event      *authEvent
	Failure    bool
	FailedIP   string
	FailedUser string
}

// classifyWinRecord reads one record. resolveSID names an account from its
// SID ("" when it cannot). ok is false for records that are neither.
func classifyWinRecord(r winRecord, resolveSID func(string) string) (winOutcome, bool) {
	d := r.Data
	ev := authEvent{At: r.Time, Key: "win:" + strconv.FormatUint(r.RecordID, 10)}
	switch r.EventID {
	case 4624:
		if serviceAccount(d["TargetUserSid"], d["TargetUserName"]) {
			return winOutcome{}, false
		}
		ev.User = qualified(d["TargetDomainName"], d["TargetUserName"])
		ip := addrOrEmpty(d["IpAddress"])
		switch d["LogonType"] {
		case "2", "11":
			ev.Type = "console.login"
		case "10":
			ev.Type, ev.SourceIP = "rdp.login", ip
		case "3":
			// File shares and management tools log on over the network all
			// day on a LAN; only a logon from the internet is worth a line.
			if ip == "" || !isPublicAddr(ip) {
				return winOutcome{}, false
			}
			ev.Type, ev.SourceIP, ev.Auth = "network.login", ip, d["AuthenticationPackageName"]
		default:
			return winOutcome{}, false
		}
		return winOutcome{Event: &ev}, true
	case 4625:
		return winOutcome{Failure: true, FailedIP: addrOrEmpty(d["IpAddress"]), FailedUser: d["TargetUserName"]}, true
	case 4720:
		ev.Type = "account.created"
		ev.User = qualified(d["TargetDomainName"], d["TargetUserName"])
		ev.By = qualified(d["SubjectDomainName"], d["SubjectUserName"])
		return winOutcome{Event: &ev}, true
	case 4732:
		if d["TargetSid"] != administratorsSID {
			return winOutcome{}, false
		}
		ev.Type = "account.admin_granted"
		ev.Group = d["TargetUserName"] // localised: "Administrators", "Administradores", ...
		ev.By = qualified(d["SubjectDomainName"], d["SubjectUserName"])
		// Local accounts come with MemberName "-": name them from the SID.
		ev.User = d["MemberName"]
		if ev.User == "" || ev.User == "-" {
			ev.User = resolveSID(d["MemberSid"])
		}
		if ev.User == "" {
			ev.User = d["MemberSid"]
		}
		if ev.User == "" {
			return winOutcome{}, false
		}
		return winOutcome{Event: &ev}, true
	case 1102:
		ev.Type = "audit.log_cleared"
		ev.By = qualified(d["SubjectDomainName"], d["SubjectUserName"])
		return winOutcome{Event: &ev}, true
	}
	return winOutcome{}, false
}

// serviceAccount is true for the logons Windows makes for itself: the
// built-in service accounts, Desktop Window Manager and font-driver sessions,
// and computer accounts.
func serviceAccount(sid, name string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-7":
		return true
	}
	upper := strings.ToUpper(name)
	switch upper {
	case "", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON":
		return true
	}
	return strings.HasPrefix(upper, "DWM-") || strings.HasPrefix(upper, "UMFD-") || strings.HasSuffix(name, "$")
}

// qualified is DOMAIN\name, or name alone when there is no domain.
func qualified(domain, name string) string {
	if name == "" || name == "-" {
		return ""
	}
	if domain == "" || domain == "-" {
		return name
	}
	return domain + `\` + name
}

func addrOrEmpty(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isPublicAddr is true for an address that can be routed on the internet.
func isPublicAddr(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return !(a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() ||
		a.IsMulticast() || cgnat.Contains(a))
}
