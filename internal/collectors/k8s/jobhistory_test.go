package k8s

import (
	"testing"
	"time"
)

// A CronJob keeps its last failed runs as history (failedJobsHistoryLimit).
// Once a later run succeeds those Jobs describe the past: the CronJob is not
// failing, and must not stay degraded until the history is pruned.
func TestFailedJobSupersededByLaterSuccessIsHistory(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	jobs := []Job{
		ownedJob("app", "reaper", "2026-10-19T08:43:00Z", "Failed"),
		ownedJob("app", "reaper", "2026-10-19T08:44:00Z", "Failed"),
		ownedJob("app", "reaper", "2026-10-20T16:30:00Z", "Complete"),
		ownedJob("app", "nudge", "2026-10-19T04:07:00Z", "Complete"),
		ownedJob("app", "nudge", "2026-10-20T04:07:00Z", "Failed"),
	}
	obs, counts := c.observe(nil, nil, jobs, nil, nil, nil, time.Now())

	if counts.jobsFailing != 1 {
		t.Errorf("jobsFailing = %d, want 1 (only nudge's latest run)", counts.jobsFailing)
	}
	if len(counts.degraded) != 1 || counts.degraded[0] != "app/CronJob/nudge" {
		t.Errorf("degraded = %v, want [app/CronJob/nudge]", counts.degraded)
	}
	for _, o := range obs {
		if o.kind == "job" && o.owner == "CronJob/reaper" && !o.healthy {
			t.Errorf("superseded run %s reported unhealthy", o.name)
		}
	}
}

// A run still in progress does not supersede the failure before it: until it
// finishes, the last finished run is the one that failed.
func TestRunningJobDoesNotSupersedeFailure(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	jobs := []Job{
		ownedJob("app", "reaper", "2026-10-20T16:29:00Z", "Failed"),
		ownedJob("app", "reaper", "2026-10-20T16:30:00Z", ""),
	}
	_, counts := c.observe(nil, nil, jobs, nil, nil, nil, time.Now())
	if counts.jobsFailing != 1 || len(counts.degraded) != 1 {
		t.Errorf("jobsFailing = %d, degraded = %v; want the failure to stand", counts.jobsFailing, counts.degraded)
	}
}

// A Job nobody owns has no later run to supersede it.
func TestUnownedFailedJobStillFails(t *testing.T) {
	c := NewCollector("h", WithConfig(Config{Host: "https://x:443"}))
	j := Job{Metadata: ObjectMeta{Namespace: "app", Name: "migrate", CreationTimestamp: "2026-10-19T08:00:00Z"}}
	j.Status.Conditions = []JobCondition{{Type: "Failed", Status: "True"}}
	_, counts := c.observe(nil, nil, []Job{j}, nil, nil, nil, time.Now())
	if counts.jobsFailing != 1 {
		t.Errorf("jobsFailing = %d, want 1", counts.jobsFailing)
	}
}
