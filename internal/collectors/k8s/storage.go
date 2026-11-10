package k8s

// Kubelet stats are read directly with the projected service-account token.
// nodes/stats is sufficient; nodes/proxy (which can allow container execution)
// is deliberately not used. The cluster CA must verify the kubelet certificate.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type filesystemStats struct {
	CapacityBytes  *float64 `json:"capacityBytes"`
	AvailableBytes *float64 `json:"availableBytes"`
}
type volumeStats struct {
	filesystemStats
	PVCRef *struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"pvcRef"`
}
type nodeSummary struct {
	Node struct {
		FS filesystemStats `json:"fs"`
	} `json:"node"`
	Pods []struct {
		PodRef struct {
			Name string `json:"name"`
		} `json:"podRef"`
		Volumes []volumeStats `json:"volume"`
	} `json:"pods"`
}
type storageUsage struct {
	// Collected is false when no kubelet was polled this cycle; the counts
	// below are then not zero, but unknown.
	Collected               bool
	NodePercent, PVCPercent *float64
	FailedNodes             int
	Filesystems             map[string]filesystemStats
	// VolumePods names a pod that mounts each claim, keyed like Filesystems.
	VolumePods    map[string]string
	ForecastReady int
	// AtRisk lists every filesystem expected to cause trouble, worst first.
	AtRisk []storageRisk
}

func filesystemUsedPercent(s filesystemStats) *float64 {
	if s.CapacityBytes == nil || s.AvailableBytes == nil || *s.CapacityBytes <= 0 || *s.AvailableBytes < 0 || *s.AvailableBytes > *s.CapacityBytes {
		return nil
	}
	return ptrFloat((1 - *s.AvailableBytes / *s.CapacityBytes) * 100)
}
func maximize(dst **float64, v *float64) {
	if v != nil && (*dst == nil || *v > **dst) {
		*dst = v
	}
}
func summarizeStorage(s nodeSummary) storageUsage {
	out := storageUsage{NodePercent: filesystemUsedPercent(s.Node.FS)}
	for _, p := range s.Pods {
		for _, v := range p.Volumes {
			if v.PVCRef != nil {
				maximize(&out.PVCPercent, filesystemUsedPercent(v.filesystemStats))
			}
		}
	}
	return out
}
func (c *Client) nodeStorage(ctx context.Context, n Node) (storageUsage, error) {
	var ip string
	for _, a := range n.Status.Addresses {
		if a.Type == "InternalIP" {
			parsed := net.ParseIP(a.Address)
			if parsed != nil && !parsed.IsLoopback() && !parsed.IsUnspecified() {
				ip = a.Address
				break
			}
		}
	}
	if ip == "" {
		return storageUsage{}, fmt.Errorf("node has no internal IP")
	}
	token, err := c.token()
	if err != nil {
		return storageUsage{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(ip, "10250")+"/stats/summary", nil)
	if err != nil {
		return storageUsage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := *c.list
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return storageUsage{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return storageUsage{}, fmt.Errorf("kubelet stats HTTP %d", res.StatusCode)
	}
	const maxSummaryBytes = 4 << 20
	b, err := io.ReadAll(io.LimitReader(res.Body, maxSummaryBytes+1))
	if err != nil {
		return storageUsage{}, err
	}
	if len(b) > maxSummaryBytes {
		return storageUsage{}, fmt.Errorf("kubelet summary too large")
	}
	var s nodeSummary
	if err = json.Unmarshal(b, &s); err != nil {
		return storageUsage{}, err
	}
	out := summarizeStorage(s)
	out.Filesystems = map[string]filesystemStats{"node:" + n.Metadata.Name: s.Node.FS}
	out.VolumePods = map[string]string{}
	for _, p := range s.Pods {
		for _, v := range p.Volumes {
			if v.PVCRef != nil {
				key := "pvc:" + v.PVCRef.Namespace + "/" + v.PVCRef.Name
				out.Filesystems[key] = v.filesystemStats
				out.VolumePods[key] = p.PodRef.Name
			}
		}
	}
	return out, nil
}
func (c *Collector) collectStorage(ctx context.Context, nodes []Node) storageUsage {
	out := storageUsage{Collected: true, Filesystems: make(map[string]filesystemStats), VolumePods: make(map[string]string)}
	if len(nodes) > 32 {
		out.FailedNodes = len(nodes) - 32
		nodes = nodes[:32]
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	// Bound work independently of cluster size. Skipped nodes are reported as
	// missing coverage rather than silently pretending every filesystem was read.
	for _, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// One retry, for the same reason as the exporter scrapes: a
			// single lost request is not an unreachable kubelet.
			v, err := retryOnce(ctx, func() (storageUsage, error) { return c.client.nodeStorage(ctx, n) })
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out.FailedNodes++
				c.logger.Debug("kubernetes: kubelet storage unavailable", "node", n.Metadata.Name, "error", err)
				return
			}
			for key, fs := range v.Filesystems {
				if old, ok := out.Filesystems[key]; !ok || (fs.AvailableBytes != nil && (old.AvailableBytes == nil || *fs.AvailableBytes < *old.AvailableBytes)) {
					out.Filesystems[key] = fs
				}
			}
			for key, pod := range v.VolumePods {
				out.VolumePods[key] = pod
			}
			maximize(&out.NodePercent, v.NodePercent)
			maximize(&out.PVCPercent, v.PVCPercent)
		}()
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storageHistory == nil {
		c.storageHistory = make(map[string][]storagePoint)
	}
	out.ForecastReady, out.AtRisk = updateStorageForecast(c.storageHistory, out.Filesystems, time.Now())
	return out
}

// A filesystem's free space is sampled every sampleEvery and kept for
// forecastWindow. A restart, a resize or a gap over maxSampleGap starts the
// window again. A data volume with less than minForecastHistory behind it has
// no forecast: it is left out of the "ready" count, never reported as fine.
const (
	sampleEvery        = 15 * time.Minute
	forecastWindow     = 72 * time.Hour
	minForecastHistory = 24 * time.Hour
	maxSampleGap       = 30 * time.Minute
	maxStoragePoints   = int(forecastWindow/sampleEvery) + 1
	maxTrackedVolumes  = 2048

	// A data volume is reported when it is at least half full and on course
	// to fill within the horizon, having already lost a real share of itself.
	forecastHorizon   = 7 * 24 * time.Hour
	minUsedPercent    = 50.0
	minDropOfCapacity = 0.01
	riskFilling       = "filling"
	riskPressure      = "pressure"
	maxReportedAtRisk = 20

	// The kubelet's defaults: it starts deleting unused images when the disk
	// they live on is 85% full (imageGCHighThresholdPercent) and starts
	// evicting pods when 10% is left (nodefs.available).
	nodeImageGCPercent  = 85.0
	nodeEvictionPercent = 90.0
	nodeGCGrace         = 30 * time.Minute
)

// storagePoint is one sample of a filesystem's free space.
type storagePoint struct {
	At                  time.Time
	Available, Capacity float64
}

// storageRisk is one filesystem the agent expects to cause trouble, with the
// numbers behind that judgement so the platform can say which disk, how full
// and how fast.
type storageRisk struct {
	// Key is "pvc:<namespace>/<name>" or "node:<name>".
	Key string
	// Reason is riskFilling (a data volume on course to fill) or riskPressure
	// (a node disk the kubelet is not keeping below its own thresholds).
	Reason              string
	Capacity, Available float64
	// ChangePerHour is the fitted change in free bytes per hour, negative
	// while filling. Zero for riskPressure, which is not a forecast.
	ChangePerHour float64
	// HistoryHours is how much history the judgement rests on.
	HistoryHours float64
}

// hoursLeft is how long the free space lasts at the fitted rate.
func (r storageRisk) hoursLeft() float64 {
	if r.ChangePerHour >= 0 {
		return forecastHorizon.Hours() * 1000
	}
	return r.Available / -r.ChangePerHour
}

// storageRiskLabels are the labels a risk's metrics carry.
func storageRiskLabels(r storageRisk, volumePods map[string]string) map[string]string {
	labels := map[string]string{"reason": r.Reason}
	if name, ok := strings.CutPrefix(r.Key, "node:"); ok {
		labels["kind"] = "node"
		labels["name"] = name
		return labels
	}
	labels["kind"] = "volume"
	ref := strings.TrimPrefix(r.Key, "pvc:")
	if ns, name, ok := strings.Cut(ref, "/"); ok {
		labels["namespace"] = ns
		labels["name"] = name
	} else {
		labels["name"] = ref
	}
	if pod := volumePods[r.Key]; pod != "" {
		labels["pod"] = pod
	}
	return labels
}

// updateStorageForecast records the current reading of every filesystem and
// returns how many could be judged and which are at risk, soonest first.
//
// Data volumes and node disks are judged differently. A data volume only
// grows until someone acts, so its trend is extrapolated (volumeFillRisk). A
// node's disk holds container images, which the kubelet deletes by itself
// once the disk is 85% full: it fills and empties by design, and a straight
// line through it predicts an exhaustion that never comes (nodeDiskRisk).
func updateStorageForecast(history map[string][]storagePoint, current map[string]filesystemStats, now time.Time) (ready int, risks []storageRisk) {
	for key, points := range history {
		if _, ok := current[key]; !ok && (len(points) == 0 || now.Sub(points[len(points)-1].At) > maxSampleGap) {
			delete(history, key)
		}
	}
	for key, fs := range current {
		percent := filesystemUsedPercent(fs)
		if percent == nil {
			delete(history, key)
			continue
		}
		if _, ok := history[key]; !ok && len(history) >= maxTrackedVolumes {
			continue
		}
		points := history[key]
		if len(points) > 0 {
			last := points[len(points)-1]
			if last.Capacity != *fs.CapacityBytes || now.Sub(last.At) > maxSampleGap || now.Before(last.At) {
				points = nil
			}
		}
		cutoff := now.Add(-forecastWindow)
		i := 0
		for i < len(points) && points[i].At.Before(cutoff) {
			i++
		}
		points = points[i:]
		if len(points) == 0 || now.Sub(points[len(points)-1].At) >= sampleEvery {
			points = append(points, storagePoint{now, *fs.AvailableBytes, *fs.CapacityBytes})
		}
		if len(points) > maxStoragePoints {
			points = points[len(points)-maxStoragePoints:]
		}
		history[key] = points

		risk := storageRisk{Key: key, Capacity: *fs.CapacityBytes, Available: *fs.AvailableBytes, HistoryHours: now.Sub(points[0].At).Hours()}
		if strings.HasPrefix(key, "node:") {
			ready++
			if nodeDiskRisk(points, *percent, now) {
				risk.Reason = riskPressure
				risks = append(risks, risk)
			}
			continue
		}
		if now.Sub(points[0].At) < minForecastHistory {
			continue
		}
		ready++
		if perHour, ok := volumeFillRisk(points, *percent); ok {
			risk.Reason = riskFilling
			risk.ChangePerHour = perHour
			risks = append(risks, risk)
		}
	}
	sort.Slice(risks, func(a, b int) bool {
		if risks[a].Reason != risks[b].Reason {
			return risks[a].Reason == riskPressure
		}
		if ha, hb := risks[a].hoursLeft(), risks[b].hoursLeft(); ha != hb {
			return ha < hb
		}
		return risks[a].Key < risks[b].Key
	})
	return
}

// trend is the least-squares change in free bytes per hour across points.
func trend(points []storagePoint) (perHour float64, ok bool) {
	if len(points) < 2 {
		return 0, false
	}
	var sx, sy, sxx, sxy float64
	for _, p := range points {
		x := p.At.Sub(points[0].At).Hours()
		sx += x
		sy += p.Available
		sxx += x * x
		sxy += x * p.Available
	}
	n := float64(len(points))
	denom := n*sxx - sx*sx
	if denom <= 0 {
		return 0, false
	}
	return (n*sxy - sx*sy) / denom, true
}

// volumeFillRisk reports whether a data volume is on course to fill within
// the horizon, and the fitted rate. One busy day must not predict a week, so
// the fall has to be a trend and not an event:
//
//   - free space is falling across the whole window AND across each half of
//     it. A burst confined to the last hours, or a fill that has since
//     stopped, fails one half;
//   - the volume has lost at least 1% of its capacity over the window;
//   - it is at least half full, and at the fitted rate the rest is gone
//     within seven days.
//
// A sawtooth (WAL recycled, a table compressed) that still trends down
// passes: the fit runs through the teeth.
func volumeFillRisk(points []storagePoint, usedPercent float64) (perHour float64, atRisk bool) {
	if usedPercent < minUsedPercent || len(points) < 8 {
		return 0, false
	}
	perHour, ok := trend(points)
	if !ok || perHour >= 0 {
		return 0, false
	}
	mid := len(points) / 2
	for _, half := range [][]storagePoint{points[:mid+1], points[mid:]} {
		if h, ok := trend(half); !ok || h >= 0 {
			return 0, false
		}
	}
	last := points[len(points)-1]
	if points[0].Available-last.Available < minDropOfCapacity*last.Capacity {
		return 0, false
	}
	if last.Available/-perHour > forecastHorizon.Hours() {
		return 0, false
	}
	return perHour, true
}

// nodeDiskRisk reports whether a node's disk is beyond what the kubelet
// handles by itself: at the eviction line now, or above the image
// garbage-collection threshold for nodeGCGrace, which means reclaiming images
// is not bringing it back down.
func nodeDiskRisk(points []storagePoint, usedPercent float64, now time.Time) bool {
	if usedPercent >= nodeEvictionPercent {
		return true
	}
	if usedPercent < nodeImageGCPercent {
		return false
	}
	for i := len(points) - 1; i >= 0; i-- {
		p := points[i]
		if (1-p.Available/p.Capacity)*100 < nodeImageGCPercent {
			return false
		}
		if now.Sub(p.At) >= nodeGCGrace {
			return true
		}
	}
	return false
}
