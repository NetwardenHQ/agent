package agent

import (
	"time"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

const (
	// maxBacklogMetrics bounds what is kept through an outage: about an hour
	// of a busy host's readings, and about 2 MB of memory.
	maxBacklogMetrics = 10_000

	// maxBacklogAge is how old a kept reading may be and still be sent. The
	// server stores readings up to a day old; a reading older than this is
	// worth less than the request it would ride in.
	maxBacklogAge = 2 * time.Hour
)

// backlog keeps the readings of posts that failed, oldest first, so that an
// outage on the way to the server leaves no hole in the host's history. Each
// reading carries the time it was taken, and the server stores it at that
// time.
//
// Only the report loop uses it; it is not safe for concurrent use.
type backlog struct {
	items  []metrics.Metric
	max    int
	maxAge time.Duration
}

func newBacklog() *backlog {
	return &backlog{max: maxBacklogMetrics, maxAge: maxBacklogAge}
}

// add appends readings that could not be delivered. When the backlog is
// full the oldest are dropped: the most recent history is worth the most.
func (b *backlog) add(ms []metrics.Metric) {
	if b == nil || len(ms) == 0 {
		return
	}
	b.items = append(b.items, ms...)
	b.trim()
}

// restore puts readings taken with take back at the front, in order, after
// the post that carried them failed.
func (b *backlog) restore(ms []metrics.Metric) {
	if b == nil || len(ms) == 0 {
		return
	}
	b.items = append(append(make([]metrics.Metric, 0, len(ms)+len(b.items)), ms...), b.items...)
	b.trim()
}

// take removes and returns up to n of the oldest readings. Readings older
// than the age limit are discarded on the way.
func (b *backlog) take(n int, now time.Time) []metrics.Metric {
	if b == nil || n <= 0 || len(b.items) == 0 {
		return nil
	}
	cutoff := now.Add(-b.maxAge)
	fresh := 0
	for fresh < len(b.items) && b.items[fresh].Timestamp.Before(cutoff) {
		fresh++
	}
	b.items = b.items[fresh:]
	n = min(n, len(b.items))
	out := append([]metrics.Metric(nil), b.items[:n]...)
	b.items = append([]metrics.Metric(nil), b.items[n:]...)
	return out
}

func (b *backlog) len() int {
	if b == nil {
		return 0
	}
	return len(b.items)
}

func (b *backlog) trim() {
	if over := len(b.items) - b.max; over > 0 {
		b.items = append([]metrics.Metric(nil), b.items[over:]...)
	}
}
