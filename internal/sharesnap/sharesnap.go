// Package sharesnap reads the share snapshots Synology's Snapshot Replication
// keeps under /volumeN/@sharesnap/<share>/<snapshot>/. The snapshot names
// carry the time they were taken ("GMT-06-2026.11.13-10.15.01"), and the
// directories that hold them are readable by any user, so no privilege is
// needed to tell when each share was last snapshotted.
package sharesnap

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultVolumes matches DSM's data volumes.
const DefaultVolumes = "/volume*"

// Snapshot is one snapshot of a share.
type Snapshot struct {
	Name string
	Time time.Time
}

// Share is a share with snapshots, newest first.
type Share struct {
	Name      string
	Dir       string // /volumeN/@sharesnap/<share>
	Volume    string // /volumeN
	Snapshots []Snapshot
}

var nameRe = regexp.MustCompile(`^GMT([+-])(\d{2})(?:-(\d{2}))?-(\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2})$`)

// ParseName returns the time a snapshot was taken from its name.
func ParseName(name string) (time.Time, bool) {
	m := nameRe.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	hours, _ := strconv.Atoi(m[2])
	minutes := 0
	if m[3] != "" {
		minutes, _ = strconv.Atoi(m[3])
	}
	offset := hours*3600 + minutes*60
	if m[1] == "-" {
		offset = -offset
	}
	t, err := time.ParseInLocation("2006.01.02-15.04.05", m[4], time.FixedZone("", offset))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Shares lists every share with at least one snapshot, by name.
func Shares(volumes string) ([]Share, error) {
	vols, err := filepath.Glob(volumes)
	if err != nil {
		return nil, err
	}
	var out []Share
	for _, vol := range vols {
		base := filepath.Join(vol, "@sharesnap")
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			s := Share{Name: ent.Name(), Dir: filepath.Join(base, ent.Name()), Volume: vol}
			s.Snapshots = list(s.Dir)
			if len(s.Snapshots) > 0 {
				out = append(out, s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func list(dir string) []Snapshot {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var snaps []Snapshot
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		if t, ok := ParseName(ent.Name()); ok {
			snaps = append(snaps, Snapshot{Name: ent.Name(), Time: t})
		}
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Time.After(snaps[j].Time) })
	return snaps
}

// Interval is the share's usual time between snapshots: the median gap
// between its newest few. Zero with fewer than two snapshots.
func (s Share) Interval() time.Duration {
	n := len(s.Snapshots)
	if n > 7 {
		n = 7
	}
	if n < 2 {
		return 0
	}
	gaps := make([]time.Duration, 0, n-1)
	for i := 0; i+1 < n; i++ {
		gaps = append(gaps, s.Snapshots[i].Time.Sub(s.Snapshots[i+1].Time))
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	return gaps[len(gaps)/2]
}

// Locate finds the share a live path belongs to, and the path inside it, so
// the same file can be looked up in the share's snapshots.
func Locate(path, volumes string) (Share, string, bool) {
	shares, err := Shares(volumes)
	if err != nil {
		return Share{}, "", false
	}
	clean := filepath.Clean(path)
	for _, s := range shares {
		root := filepath.Join(s.Volume, s.Name) + string(filepath.Separator)
		if strings.HasPrefix(clean, root) {
			return s, strings.TrimPrefix(clean, root), true
		}
	}
	return Share{}, "", false
}
