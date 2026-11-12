package k8s

import (
	"sort"
	"strconv"
	"strings"
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
	// spec.timeZone; empty means UTC. The UI recomputes a stale NextRun from
	// Schedule in this zone.
	TimeZone string `json:"time_zone,omitempty"`
	Active   int    `json:"active"`
	// Outcome of the most recent finished Job this CronJob owns.
	LastOutcome string `json:"last_outcome,omitempty"` // succeeded | failed | (empty: never run)
	FailedRuns  int    `json:"failed_runs"`
	// LastFailure describes the most recent run when it failed.
	LastFailure *cronJobFailure `json:"last_failure,omitempty"`
}

// cronJobFailure is what Kubernetes says about a failed run.
type cronJobFailure struct {
	// Job is the failed run's name, which `kubectl logs job/<name>` takes
	// while the Job is kept.
	Job string `json:"job"`
	// Reason and Message are the Job's Failed condition, for example
	// BackoffLimitExceeded, "Job has reached the specified backoff limit".
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
	// At is when the Job gave up, RFC3339.
	At string `json:"at,omitempty"`
	// Attempts is how many of its pods failed.
	Attempts int `json:"attempts"`
	// Manual is true for a run started by hand (kubectl create job
	// --from=cronjob/...), not by the schedule.
	Manual bool `json:"manual,omitempty"`
}

// scheduledRunName reports whether a Job name is one the CronJob controller
// gives a scheduled run: the CronJob's name, a dash, and the scheduled time
// in minutes since the epoch. Anything else was created by hand.
func scheduledRunName(cronJob, job string) bool {
	suffix, ok := strings.CutPrefix(job, cronJob+"-")
	if !ok || len(suffix) < 8 {
		return false
	}
	_, err := strconv.ParseUint(suffix, 10, 64)
	return err == nil
}

// failureOf describes a failed Job.
func failureOf(cronJob string, j Job) *cronJobFailure {
	f := &cronJobFailure{Job: j.Metadata.Name, Attempts: j.Status.Failed, Manual: !scheduledRunName(cronJob, j.Metadata.Name)}
	for _, c := range j.Status.Conditions {
		if c.Type == "Failed" && c.Status == "True" {
			f.Reason, f.Message, f.At = c.Reason, c.Message, c.LastTransitionTime
		}
	}
	return f
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
		job    Job
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
			latest[key] = jobOutcome{when: when, failed: failed, job: j}
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
		if cj.Spec.TimeZone != nil {
			st.TimeZone = *cj.Spec.TimeZone
		}

		key := cj.Metadata.Namespace + "|CronJob/" + cj.Metadata.Name
		st.FailedRuns = failures[key]
		if o, ok := latest[key]; ok {
			if o.failed {
				st.LastOutcome = "failed"
				st.LastFailure = failureOf(cj.Metadata.Name, o.job)
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

// maxFailedCronJobSeries bounds the per-CronJob series one report carries.
const maxFailedCronJobSeries = 20

// failedCronJobSeries labels one k8s_cronjob_failed series per CronJob whose
// last run failed, so an alert can say which job, in which namespace, and
// what Kubernetes said, not only how many. The message is cut to 200
// characters.
func failedCronJobSeries(r cronJobReport) []map[string]string {
	var out []map[string]string
	for _, cj := range r.CronJobs {
		if cj.LastOutcome != "failed" || cj.LastFailure == nil || len(out) == maxFailedCronJobSeries {
			continue
		}
		f := cj.LastFailure
		message := f.Message
		if len(message) > 200 {
			message = message[:200]
		}
		out = append(out, map[string]string{
			"namespace": cj.Namespace,
			"cronjob":   cj.Name,
			"job":       f.Job,
			"reason":    f.Reason,
			"message":   message,
			"failed_at": f.At,
			"attempts":  strconv.Itoa(f.Attempts),
			"manual":    strconv.FormatBool(f.Manual),
		})
	}
	return out
}
