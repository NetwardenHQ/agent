package synology

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// reply is the envelope every DSM web API answers with.
type reply[T any] struct {
	Data    T    `json:"data"`
	Success bool `json:"success"`
}

func decode[T any](data []byte) (T, error) {
	var r reply[T]
	if err := json.Unmarshal(data, &r); err != nil {
		return r.Data, fmt.Errorf("not valid JSON: %w", err)
	}
	if !r.Success {
		return r.Data, errors.New("DSM answered success=false")
	}
	return r.Data, nil
}

// ---------------------------------------------------------------------------
// Security Advisor: SYNO.Core.SecurityScan.Status system_get
// ---------------------------------------------------------------------------

type scanStatus struct {
	Items map[string]struct {
		Fail         map[string]int `json:"fail"`
		FailSeverity string         `json:"failSeverity"`
	} `json:"items"`
	LastScanTime string `json:"lastScanTime"`
	SysStatus    string `json:"sysStatus"`
}

// scanSeverities are the counts that are findings; "info" is not one.
var scanSeverities = []string{"danger", "risk", "warning", "outOfDate"}

func collectSecurityScan(e *emitter, data []byte) error {
	s, err := decode[scanStatus](data)
	if err != nil {
		return err
	}
	if s.SysStatus == "" {
		return errors.New("no scan status in the reply")
	}
	total := 0
	categories := make([]string, 0, len(s.Items))
	for name := range s.Items {
		categories = append(categories, name)
	}
	sort.Strings(categories)
	for _, name := range categories {
		item := s.Items[name]
		n := 0
		for _, sev := range scanSeverities {
			n += item.Fail[sev]
		}
		total += n
		if n > 0 {
			e.gauge("synology_security_scan_failing", float64(n), map[string]string{"category": name, "severity": item.FailSeverity})
		}
	}
	e.gauge("synology_security_scan_safe", b2f(s.SysStatus == "safe"), nil)
	e.gauge("synology_security_scan_findings", float64(total), nil)
	if ts, err := strconv.ParseInt(s.LastScanTime, 10, 64); err == nil && ts > 0 {
		e.gauge("synology_security_scan_age_seconds", e.ts.Sub(unix(ts)).Seconds(), nil)
	}
	return nil
}

// ---------------------------------------------------------------------------
// DSM updates: SYNO.Core.Upgrade.Server check
// ---------------------------------------------------------------------------

func collectUpgrade(e *emitter, data []byte) error {
	u, err := decode[struct {
		Update *struct {
			Available bool   `json:"available"`
			Version   string `json:"version"`
		} `json:"update"`
	}](data)
	if err != nil {
		return err
	}
	if u.Update == nil {
		return errors.New("no update section in the reply")
	}
	var labels map[string]string
	if u.Update.Available && u.Update.Version != "" {
		labels = map[string]string{"version": u.Update.Version}
	}
	e.gauge("synology_update_available", b2f(u.Update.Available), labels)
	return nil
}

// ---------------------------------------------------------------------------
// Sign-ins DSM flags as abnormal: SYNO.SecurityAdvisor.LoginActivity list
// ---------------------------------------------------------------------------

type loginActivity struct {
	Items []struct {
		StrID   string `json:"str_id"`
		User    string `json:"user"`
		StrArgs struct {
			City        string `json:"city"`
			CountryCode string `json:"country_code"`
			IP          string `json:"ip"`
			Protocol    string `json:"protocol"`
			Timestamp   string `json:"timestamp"`
			User        string `json:"user"`
		} `json:"str_args"`
	} `json:"items"`
}

// collectLogins reports sign-ins newer than the last one reported. The
// first read only sets the baseline, so history is not replayed as news.
func (c *Collector) collectLogins(e *emitter, data []byte) error {
	a, err := decode[loginActivity](data)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	newest := c.lastLogin
	fresh := 0
	for _, it := range a.Items {
		if it.StrID != "abnormal_login" {
			continue
		}
		ts, err := strconv.ParseInt(it.StrArgs.Timestamp, 10, 64)
		if err != nil {
			continue
		}
		if ts > newest {
			newest = ts
		}
		if !c.baselined || ts <= c.lastLogin {
			continue
		}
		fresh++
		user := it.StrArgs.User
		if user == "" {
			user = it.User
		}
		e.gauge("synology_abnormal_login", 1, map[string]string{
			"user": user, "ip": it.StrArgs.IP, "country": it.StrArgs.CountryCode,
			"city": it.StrArgs.City, "protocol": it.StrArgs.Protocol,
		})
	}
	c.lastLogin = newest
	c.baselined = true
	e.gauge("synology_abnormal_logins_new", float64(fresh), nil)
	return nil
}

// ---------------------------------------------------------------------------
// Container Manager: SYNO.Docker.Container list
// ---------------------------------------------------------------------------

func collectContainers(e *emitter, data []byte) error {
	l, err := decode[struct {
		Containers []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"containers"`
	}](data)
	if err != nil {
		return err
	}
	stopped := 0
	for _, ct := range l.Containers {
		running := ct.Status == "running"
		if !running {
			stopped++
		}
		e.gauge("synology_container_running", b2f(running), map[string]string{"container": ct.Name, "status": ct.Status})
	}
	e.gauge("synology_containers_stopped", float64(stopped), nil)
	return nil
}

// ---------------------------------------------------------------------------
// RAID: /proc/mdstat (no privileges needed)
// ---------------------------------------------------------------------------

var (
	mdHeader = regexp.MustCompile(`^(md\d+)\s*:\s*\S+\s+(raid\d+|linear)?`)
	mdCounts = regexp.MustCompile(`\[(\d+)/(\d+)\]\s+\[([U_]+)\]`)
)

func (c *Collector) collectMdstat(e *emitter) error {
	data, err := os.ReadFile(c.mdstat)
	if err != nil {
		return err
	}
	degraded, missing := 0, 0
	var array, level string
	for _, line := range strings.Split(string(data), "\n") {
		if m := mdHeader.FindStringSubmatch(line); m != nil {
			array, level = m[1], m[2]
			continue
		}
		m := mdCounts.FindStringSubmatch(line)
		if m == nil || array == "" {
			continue
		}
		want, _ := strconv.Atoi(m[1])
		have, _ := strconv.Atoi(m[2])
		bad := have < want || strings.Contains(m[3], "_")
		if bad {
			degraded++
		}
		// Every drive carries a member of every array on DSM, so the most
		// members any one array lacks is how many drives are gone.
		if gone := strings.Count(m[3], "_"); gone > missing {
			missing = gone
		}
		if want-have > missing {
			missing = want - have
		}
		e.gauge("synology_md_degraded", b2f(bad), map[string]string{"array": array, "level": level})
		array = ""
	}
	e.gauge("synology_md_arrays_degraded", float64(degraded), nil)
	e.gauge("synology_disks_missing", float64(missing), nil)
	return nil
}
