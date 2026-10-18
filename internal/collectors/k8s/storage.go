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
		Volumes []volumeStats `json:"volume"`
	} `json:"pods"`
}
type storageUsage struct {
	// Collected is false when no kubelet was polled this cycle; the counts
	// below are then not zero, but unknown.
	Collected                     bool
	NodePercent, PVCPercent       *float64
	FailedNodes                   int
	Filesystems                   map[string]filesystemStats
	ForecastReady, ForecastAtRisk int
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
	for _, p := range s.Pods {
		for _, v := range p.Volumes {
			if v.PVCRef != nil {
				out.Filesystems["pvc:"+v.PVCRef.Namespace+"/"+v.PVCRef.Name] = v.filesystemStats
			}
		}
	}
	return out, nil
}
func (c *Collector) collectStorage(ctx context.Context, nodes []Node) storageUsage {
	out := storageUsage{Collected: true, Filesystems: make(map[string]filesystemStats)}
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
			v, err := c.client.nodeStorage(ctx, n)
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
	out.ForecastReady, out.ForecastAtRisk = updateStorageForecast(c.storageHistory, out.Filesystems, time.Now())
	return out
}

// storagePoint is one sample of a bounded, per-filesystem trend. A restart, a
// resize or a gap over 30 minutes resets the window. Unknown history is reported separately, never as a valid forecast.
type storagePoint struct {
	At                  time.Time
	Available, Capacity float64
}

func updateStorageForecast(history map[string][]storagePoint, current map[string]filesystemStats, now time.Time) (ready, risk int) {
	for key, points := range history {
		if _, ok := current[key]; !ok && (len(points) == 0 || now.Sub(points[len(points)-1].At) > 30*time.Minute) {
			delete(history, key)
		}
	}
	for key, fs := range current {
		percent := filesystemUsedPercent(fs)
		if percent == nil {
			delete(history, key)
			continue
		}
		if _, ok := history[key]; !ok && len(history) >= 2048 {
			continue
		}
		points := history[key]
		if len(points) > 0 {
			last := points[len(points)-1]
			if last.Capacity != *fs.CapacityBytes || now.Sub(last.At) > 30*time.Minute || now.Before(last.At) {
				points = nil
			}
		}
		cutoff := now.Add(-24 * time.Hour)
		i := 0
		for i < len(points) && points[i].At.Before(cutoff) {
			i++
		}
		points = points[i:]
		if len(points) == 0 || now.Sub(points[len(points)-1].At) >= 5*time.Minute {
			points = append(points, storagePoint{now, *fs.AvailableBytes, *fs.CapacityBytes})
		}
		if len(points) > 289 {
			points = points[len(points)-289:]
		}
		history[key] = points
		if len(points) < 20 || now.Sub(points[0].At) < 6*time.Hour {
			continue
		}
		ready++
		// Least-squares decline of available bytes per hour, not differences between
		// different volumes or percentage changes caused by a volume expansion.
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
			continue
		}
		slope := (n*sxy - sx*sy) / denom
		if slope < 0 && *percent >= 50 && *fs.AvailableBytes/(-slope) <= 7*24 {
			risk++
		}
	}
	return
}
