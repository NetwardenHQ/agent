package k8s

import (
	"sort"
	"time"
	// The agent often runs in a scratch image with no /usr/share/zoneinfo,
	// where named CronJob timezones would fail to load. The embedded database
	// costs about 450 KB.
	_ "time/tzdata"
)

/*
CronJob reporting: schedule, last outcome, and when it is due next.

"Failing" means the last run failed, not that a run has ever failed. A CronJob
that failed once last month and has succeeded every day since is not a problem.
*/

// backupComponentLabel / backupComponentValue mark a CronJob as a database
// backup: `component: db-backup` in its metadata.labels. It is opt-in rather
// than inferred from names, because only a job declared to be a backup should
// be held to a backup-age threshold.
const (
	backupComponentLabel = "component"
	backupComponentValue = "db-backup"
)

// cronJobState is one row of the panel.
type cronJobState struct {
	DatabaseBackup bool   `json:"database_backup,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	Schedule       string `json:"schedule"`
	Suspended      bool   `json:"suspended"`
	LastSchedule   string `json:"last_schedule,omitempty"`
	LastSuccessful string `json:"last_successful,omitempty"`
	// RFC3339, or empty when the schedule cannot be projected (e.g. @every).
	NextRun string `json:"next_run,omitempty"`
	Active  int    `json:"active"`
	// Outcome of the most recent finished Job this CronJob owns.
	LastOutcome string `json:"last_outcome,omitempty"` // succeeded | failed | (empty: never run)
	FailedRuns  int    `json:"failed_runs"`
}

// cronJobReport is what the agent ships and the UI renders.
type cronJobReport struct {
	Cluster  string         `json:"cluster"`
	CronJobs []cronJobState `json:"cronjobs"`
}

// buildCronJobReport folds CronJobs together with the Jobs they own.
func buildCronJobReport(cluster string, cronJobs []CronJob, jobs []Job, now time.Time) cronJobReport {
	// Index the jobs by owning CronJob so each row reports an actual outcome.
	type jobOutcome struct {
		when   time.Time
		failed bool
	}
	latest := map[string]jobOutcome{}
	failures := map[string]int{}

	for _, j := range jobs {
		owner := jobOwner(j)
		if owner == "" {
			continue
		}
		key := j.Metadata.Namespace + "|" + owner

		finished, failed := jobFinished(j)
		if failed {
			failures[key]++
		}
		if !finished {
			continue
		}

		// CreationTimestamp is the only ordering signal every Job carries.
		when, err := time.Parse(time.RFC3339, j.Metadata.CreationTimestamp)
		if err != nil {
			continue
		}
		if prev, ok := latest[key]; !ok || when.After(prev.when) {
			latest[key] = jobOutcome{when: when, failed: failed}
		}
	}

	out := cronJobReport{Cluster: cluster, CronJobs: make([]cronJobState, 0, len(cronJobs))}
	for _, cj := range cronJobs {
		st := cronJobState{
			DatabaseBackup: cj.Metadata.Labels[backupComponentLabel] == backupComponentValue,
			CreatedAt:      cj.Metadata.CreationTimestamp,
			Namespace:      cj.Metadata.Namespace,
			Name:           cj.Metadata.Name,
			Schedule:       cj.Spec.Schedule,
			Suspended:      cj.Spec.Suspend != nil && *cj.Spec.Suspend,
			LastSchedule:   cj.Status.LastScheduleTime,
			LastSuccessful: cj.Status.LastSuccessfulTime,
			Active:         len(cj.Status.Active),
		}

		key := cj.Metadata.Namespace + "|CronJob/" + cj.Metadata.Name
		st.FailedRuns = failures[key]
		if o, ok := latest[key]; ok {
			if o.failed {
				st.LastOutcome = "failed"
			} else {
				st.LastOutcome = "succeeded"
			}
		}

		if !st.Suspended {
			st.NextRun = projectNextRun(cj, now)
		}
		out.CronJobs = append(out.CronJobs, st)
	}

	sort.Slice(out.CronJobs, func(i, j int) bool {
		if out.CronJobs[i].Namespace != out.CronJobs[j].Namespace {
			return out.CronJobs[i].Namespace < out.CronJobs[j].Namespace
		}
		return out.CronJobs[i].Name < out.CronJobs[j].Name
	})
	return out
}

// projectNextRun returns RFC3339, or "" when the schedule cannot be projected.
// An unreadable schedule or a timezone that cannot be loaded yields no answer
// rather than a wrong one: evaluating "0 8 * * *" for Asia/Tokyo in UTC would
// be nine hours off and look plausible.
func projectNextRun(cj CronJob, now time.Time) string {
	sched, err := parseCron(cj.Spec.Schedule)
	if err != nil {
		return ""
	}
	loc := time.UTC
	if cj.Spec.TimeZone != nil && *cj.Spec.TimeZone != "" {
		l, err := time.LoadLocation(*cj.Spec.TimeZone)
		if err != nil {
			return ""
		}
		loc = l
	}
	next, ok := sched.next(now.In(loc))
	if !ok {
		return ""
	}
	return next.UTC().Format(time.RFC3339)
}

// cronJobCounts are the alertable rollups.
type cronJobCounts struct {
	total     int
	suspended int
	failing   int // last run failed
	active    int
}

func countCronJobs(r cronJobReport) cronJobCounts {
	var c cronJobCounts
	for _, cj := range r.CronJobs {
		c.total++
		if cj.Suspended {
			c.suspended++
		}
		if cj.LastOutcome == "failed" {
			c.failing++
		}
		c.active += cj.Active
	}
	return c
}
