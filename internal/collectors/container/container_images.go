package container

import (
	"sort"
	"sync"

	"github.com/NetwardenHQ/agent/internal/metrics"
)

// imageInventory is the container-image snapshot handoff. Collect() builds the
// inventory on a collection goroutine and Snapshots() drains it on the agent
// goroutine.
type imageInventory struct {
	mu      sync.Mutex
	pending *metrics.Snapshot
}

// imageEntry is one distinct image the host is running, as reported to the
// platform as part of the container-images snapshot; its JSON shape is part of
// the agent API.
type imageEntry struct {
	// Reference is the image reference as the runtime reports it, e.g.
	// "nginx:1.27" or "ghcr.io/org/app@sha256:...". This is what a human
	// recognizes, but not a stable identity, since tags such as ":latest"
	// move.
	Reference string `json:"reference"`

	// Digest is the container's ImageID: the image config digest
	// ("sha256:..."), the stable local identity the platform dedups and
	// re-scans on. It is not the registry manifest digest of a
	// "name@sha256:..." reference. May be empty when the runtime does not
	// report an ImageID for a container.
	Digest string `json:"digest,omitempty"`

	// RunningCount / TotalCount are how many running / total containers on
	// this host use the image, so twenty replicas of one image report once.
	RunningCount int `json:"running_count"`
	TotalCount   int `json:"total_count"`
}

// buildImageInventory deduplicates a container list into a per-image inventory.
//
// The key is the digest when present, else the reference: two tags resolving
// to one digest report a single entry, and digest-less images stay separate.
func buildImageInventory(containers []Container) []imageEntry {
	type agg struct {
		reference string
		digest    string
		running   int
		total     int
	}
	byKey := map[string]*agg{}

	for _, ct := range containers {
		if ct.Image == "" && ct.ImageID == "" {
			continue
		}
		key := ct.ImageID
		if key == "" {
			key = ct.Image
		}
		a := byKey[key]
		if a == nil {
			a = &agg{reference: ct.Image, digest: ct.ImageID}
			byKey[key] = a
		}
		// Prefer a concrete reference if a later container carries one.
		if a.reference == "" {
			a.reference = ct.Image
		}
		a.total++
		if ct.Status == "running" {
			a.running++
		}
	}

	out := make([]imageEntry, 0, len(byKey))
	for _, a := range byKey {
		out = append(out, imageEntry{
			Reference:    a.reference,
			Digest:       a.digest,
			RunningCount: a.running,
			TotalCount:   a.total,
		})
	}

	// Stable ordering: running images first, then by reference, so the
	// snapshot is deterministic and diffs cleanly cycle-to-cycle.
	sort.Slice(out, func(i, j int) bool {
		if (out[i].RunningCount > 0) != (out[j].RunningCount > 0) {
			return out[i].RunningCount > 0
		}
		if out[i].Reference != out[j].Reference {
			return out[i].Reference < out[j].Reference
		}
		return out[i].Digest < out[j].Digest
	})
	return out
}

// stageImages records the image inventory for the next Snapshots() drain.
// A nil or empty inventory clears any pending snapshot rather than shipping an
// empty one, so a host that momentarily lists no containers does not overwrite
// the platform's view with "no images".
func (c *Collector) stageImages(containers []Container) {
	entries := buildImageInventory(containers)

	c.images.mu.Lock()
	defer c.images.mu.Unlock()

	if len(entries) == 0 {
		c.images.pending = nil
		return
	}

	runtimeName := ""
	if c.monitor != nil {
		if client := c.monitor.GetClient(); client != nil {
			runtimeName = client.Name()
		}
	}

	c.images.pending = &metrics.Snapshot{
		Type: metrics.SnapshotContainerImages,
		Payload: map[string]any{
			"runtime": runtimeName,
			"images":  entries,
			"count":   len(entries),
		},
	}
}

// Snapshots returns the container-image inventory from the most recent
// Collect(), then clears it. Implements metrics.SnapshotProvider.
func (c *Collector) Snapshots() []metrics.Snapshot {
	c.images.mu.Lock()
	defer c.images.mu.Unlock()

	if c.images.pending == nil {
		return nil
	}
	snap := *c.images.pending
	c.images.pending = nil
	return []metrics.Snapshot{snap}
}

// Compile-time assertion that the collector provides snapshots.
var _ metrics.SnapshotProvider = (*Collector)(nil)
