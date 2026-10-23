//go:build windows

package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Reading the Security log through the Windows Event Log API (wevtapi.dll).
// A bookmark persisted next to the agent's other state records the last event
// handed on, so a restart neither repeats nor skips events. Without one the
// first read starts 60 seconds back, like the Linux collector: no backfill.

var (
	modwevtapi            = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery          = modwevtapi.NewProc("EvtQuery")
	procEvtSeek           = modwevtapi.NewProc("EvtSeek")
	procEvtNext           = modwevtapi.NewProc("EvtNext")
	procEvtRender         = modwevtapi.NewProc("EvtRender")
	procEvtClose          = modwevtapi.NewProc("EvtClose")
	procEvtCreateBookmark = modwevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = modwevtapi.NewProc("EvtUpdateBookmark")
)

const (
	evtQueryChannelPath       = 0x1
	evtQueryForwardDirection  = 0x100
	evtRenderEventXML         = 1
	evtRenderBookmark         = 2
	evtSeekRelativeToBookmark = 4

	// maxRecordsPerRead bounds one collection; the bookmark carries the rest
	// to the next one.
	maxRecordsPerRead = 5000
	nextBatch         = 64
	nextTimeoutMS     = 1000
)

var errNoMoreItems = syscall.Errno(259) // ERROR_NO_MORE_ITEMS

// bookmarkPath is beside the FIM manifest, under the directory only SYSTEM
// and Administrators can write.
func bookmarkPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "Netwarden", "auth-bookmark.xml")
}

func evtClose(h windows.Handle) {
	if h != 0 {
		_, _, _ = procEvtClose.Call(uintptr(h))
	}
}

// evtRender renders an event (flags evtRenderEventXML) or a bookmark
// (evtRenderBookmark) as XML.
func evtRender(h windows.Handle, flags uint32) (string, error) {
	var used, props uint32
	r, _, err := procEvtRender.Call(0, uintptr(h), uintptr(flags), 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r == 0 && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return "", fmt.Errorf("EvtRender: %w", err)
	}
	buf := make([]uint16, used/2+1)
	r, _, err = procEvtRender.Call(0, uintptr(h), uintptr(flags), uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r == 0 {
		return "", fmt.Errorf("EvtRender: %w", err)
	}
	return windows.UTF16ToString(buf), nil
}

// readSecurityLog returns the Security log records since the bookmark (or,
// before there is one, from the last lookBack), and a commit that persists
// the new bookmark. Call commit only once the records' events are safely in
// the spool; until then the next read starts over from the old bookmark, and
// the platform drops the duplicates.
func readSecurityLog(lookBack time.Duration) ([]winRecord, func(), error) {
	if err := modwevtapi.Load(); err != nil {
		return nil, nil, err
	}

	var bookmark windows.Handle
	query := winSecurityQuery
	if saved, err := os.ReadFile(bookmarkPath()); err == nil && len(saved) > 0 {
		p, err := windows.UTF16PtrFromString(string(saved))
		if err == nil {
			h, _, _ := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
			bookmark = windows.Handle(h)
		}
	}
	if bookmark == 0 {
		// No bookmark yet: the collector's window (timediff is in milliseconds).
		query = fmt.Sprintf("*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4732 or EventID=1102)"+
			" and TimeCreated[timediff(@SystemTime) <= %d]]]", lookBack.Milliseconds())
		h, _, err := procEvtCreateBookmark.Call(0)
		if h == 0 {
			return nil, nil, fmt.Errorf("EvtCreateBookmark: %w", err)
		}
		bookmark = windows.Handle(h)
	}

	channel, _ := windows.UTF16PtrFromString("Security")
	q, _ := windows.UTF16PtrFromString(query)
	qh, _, err := procEvtQuery.Call(0, uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(q)),
		evtQueryChannelPath|evtQueryForwardDirection)
	if qh == 0 {
		evtClose(bookmark)
		return nil, nil, fmt.Errorf("EvtQuery Security: %w", err)
	}
	results := windows.Handle(qh)
	defer evtClose(results)

	if query == winSecurityQuery {
		// Start after the bookmarked event. Not strict: if the log has wrapped
		// past it, reading resumes at the oldest event still there.
		r, _, _ := procEvtSeek.Call(uintptr(results), 1, uintptr(bookmark), 0, evtSeekRelativeToBookmark)
		if r == 0 {
			// The bookmarked event is gone (the log was cleared, or the
			// bookmark is damaged). Drop it and read the collector's window,
			// rather than failing this read and every one after it.
			evtClose(bookmark)
			if err := os.Remove(bookmarkPath()); err != nil && !os.IsNotExist(err) {
				// Retrying would load the same bookmark and fail again.
				return nil, nil, fmt.Errorf("bookmark no longer valid and not removable: %w", err)
			}
			return readSecurityLog(lookBack)
		}
	}

	var records []winRecord
	moved := false // the bookmark points at an event read here
	handles := make([]windows.Handle, nextBatch)
	for len(records) < maxRecordsPerRead {
		var returned uint32
		r, _, err := procEvtNext.Call(uintptr(results), nextBatch, uintptr(unsafe.Pointer(&handles[0])),
			nextTimeoutMS, 0, uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			if errors.Is(err, errNoMoreItems) {
				break
			}
			evtClose(bookmark)
			return nil, nil, fmt.Errorf("EvtNext: %w", err)
		}
		for _, h := range handles[:returned] {
			xml, err := evtRender(h, evtRenderEventXML)
			if err == nil {
				if rec, err := parseWinEventXML([]byte(xml)); err == nil {
					records = append(records, rec)
				}
			}
			if r, _, _ := procEvtUpdateBookmark.Call(uintptr(bookmark), uintptr(h)); r != 0 {
				moved = true
			}
			evtClose(h)
		}
	}

	commit := func() {
		defer evtClose(bookmark)
		// A bookmark that never moved names no event to seek from; keep the
		// old one (or none, and the next read uses the window again).
		if !moved {
			return
		}
		xml, err := evtRender(bookmark, evtRenderBookmark)
		if err != nil || xml == "" {
			return
		}
		path := bookmarkPath()
		tmp := path + ".tmp"
		if os.WriteFile(tmp, []byte(xml), 0o600) == nil {
			_ = os.Rename(tmp, path)
		}
	}
	return records, commit, nil
}

// lookupSID names an account from its SID as DOMAIN\name, or "" when Windows
// cannot.
func lookupSID(s string) string {
	sid, err := windows.StringToSid(s)
	if err != nil {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	return qualified(domain, account)
}
