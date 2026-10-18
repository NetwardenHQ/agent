package k8s

import (
	"testing"
	"time"
)

func cj(ns, name, schedule string, suspend bool) CronJob {
	c := CronJob{}
	c.Metadata.Namespace, c.Metadata.Name = ns, name
	c.Spec.Schedule = schedule
	if suspend {
		s := true
		c.Spec.Suspend = &s
	}
	return c
}

func ownedJob(ns, cronName, created string, cond string) Job {
	j := Job{}
	j.Metadata.Namespace = ns
	j.Metadata.Name = cronName + "-" + created
	j.Metadata.CreationTimestamp = created
	j.Metadata.OwnerReferences = []OwnerReference{
		{Kind: "CronJob", Name: cronName, Controller: boolPtr(true)},
	}
	if cond != "" {
		j.Status.Conditions = []JobCondition{{Type: cond, Status: "True"}}
	}
	return j
}

func at(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func TestLastOutcomeIsTheMostRecentFinishedRun(t *testing.T) {
	jobs := []Job{
		ownedJob("app", "db-backup", "2026-09-12T08:00:00Z", "Failed"),
		ownedJob("app", "db-backup", "2026-09-13T08:00:00Z", "Complete"),
		ownedJob("app", "db-backup", "2026-09-14T08:00:00Z", "Complete"),
	}
	r := buildCronJobReport("app", []CronJob{cj("app", "db-backup", "0 8 * * *", false)}, jobs, at("2026-09-14T09:00:00Z"))

	got := r.CronJobs[0]
	if got.LastOutcome != "succeeded" {
		t.Errorf("LastOutcome = %q, want succeeded", got.LastOutcome)
	}
	if got.FailedRuns != 1 {
		t.Errorf("FailedRuns = %d, want 1 (history is still reported)", got.FailedRuns)
	}
	if countCronJobs(r).failing != 0 {
		t.Error("counted as failing despite its last run succeeding")
	}
}

func TestFailingCountsWhenTheLastRunFailed(t *testing.T) {
	jobs := []Job{
		ownedJob("app", "db-backup", "2026-09-13T08:00:00Z", "Complete"),
		ownedJob("app", "db-backup", "2026-09-14T08:00:00Z", "Failed"),
	}
	r := buildCronJobReport("app", []CronJob{cj("app", "db-backup", "0 8 * * *", false)}, jobs, at("2026-09-14T09:00:00Z"))
	if r.CronJobs[0].LastOutcome != "failed" {
		t.Fatalf("LastOutcome = %q", r.CronJobs[0].LastOutcome)
	}
	if countCronJobs(r).failing != 1 {
		t.Error("a cronjob whose last run failed must count as failing")
	}
}

func TestStillRunningJobsDoNotSetAnOutcome(t *testing.T) {
	jobs := []Job{ownedJob("app", "db-backup", "2026-09-14T08:00:00Z", "")}
	r := buildCronJobReport("app", []CronJob{cj("app", "db-backup", "0 8 * * *", false)}, jobs, at("2026-09-14T08:05:00Z"))
	if r.CronJobs[0].LastOutcome != "" {
		t.Errorf("an unfinished job set LastOutcome = %q", r.CronJobs[0].LastOutcome)
	}
}

func TestSuspendedHasNoNextRun(t *testing.T) {
	r := buildCronJobReport("app", []CronJob{cj("app", "paused", "0 8 * * *", true)}, nil, at("2026-09-14T09:00:00Z"))
	if r.CronJobs[0].NextRun != "" {
		t.Errorf("suspended cronjob projected a next run of %q", r.CronJobs[0].NextRun)
	}
	if countCronJobs(r).suspended != 1 {
		t.Error("not counted as suspended")
	}
}

func TestNextRunIsProjected(t *testing.T) {
	r := buildCronJobReport("app", []CronJob{cj("app", "db-backup", "0 8 * * *", false)}, nil, at("2026-09-14T09:00:00Z"))
	if want := "2026-09-15T08:00:00Z"; r.CronJobs[0].NextRun != want {
		t.Errorf("NextRun = %q, want %q", r.CronJobs[0].NextRun, want)
	}
}

func TestUnprojectableScheduleLeavesNextRunEmpty(t *testing.T) {
	r := buildCronJobReport("app", []CronJob{cj("app", "odd", "@every 5m", false)}, nil, at("2026-09-14T09:00:00Z"))
	if r.CronJobs[0].NextRun != "" {
		t.Errorf("projected %q from an unsupported schedule", r.CronJobs[0].NextRun)
	}
}

func TestUnrelatedJobsAreIgnored(t *testing.T) {
	j := Job{}
	j.Metadata.Namespace = "app"
	j.Metadata.CreationTimestamp = "2026-09-14T08:00:00Z"
	j.Status.Conditions = []JobCondition{{Type: "Failed", Status: "True"}}
	r := buildCronJobReport("app", []CronJob{cj("app", "db-backup", "0 8 * * *", false)}, []Job{j}, at("2026-09-14T09:00:00Z"))
	if r.CronJobs[0].FailedRuns != 0 || r.CronJobs[0].LastOutcome != "" {
		t.Error("an ownerless Job was attributed to a CronJob")
	}
}

func TestBackupAgeIncludesNeverSuccessfulBackupButNotOrdinaryCron(t *testing.T) {
	now := time.Now()
	c := NewCollector("test")
	cron := cronJobReport{CronJobs: []cronJobState{
		{Name: "daily-backup", DatabaseBackup: true, CreatedAt: now.Add(-27 * time.Hour).Format(time.RFC3339)},
		{Name: "weekly-report", CreatedAt: now.Add(-365 * 24 * time.Hour).Format(time.RFC3339)},
	}}
	for _, m := range c.emitMetrics(1, clusterCounts{}, usageSnapshot{}, cron, cnpgReport{}, ingressReport{}, now) {
		if m.Name == "k8s_database_backup_max_age_seconds" {
			if m.Value < 27*3600 || m.Value > 27*3600+1 {
				t.Fatalf("unexpected age %v", m.Value)
			}
			return
		}
	}
	t.Fatal("missing backup age")
}

// A suspended backup job, such as one retired after a database rename, does
// not count towards the backup age.
func TestBackupAgeIgnoresSuspendedBackup(t *testing.T) {
	now := time.Now()
	c := NewCollector("test")
	cron := cronJobReport{CronJobs: []cronJobState{
		{Name: "live-backup", DatabaseBackup: true, LastSuccessful: now.Add(-2 * time.Hour).Format(time.RFC3339)},
		{Name: "retired-backup", DatabaseBackup: true, Suspended: true, LastSuccessful: now.Add(-11 * 24 * time.Hour).Format(time.RFC3339)},
	}}
	for _, m := range c.emitMetrics(1, clusterCounts{}, usageSnapshot{}, cron, cnpgReport{}, ingressReport{}, now) {
		if m.Name == "k8s_database_backup_max_age_seconds" {
			if m.Value < 2*3600 || m.Value > 2*3600+1 {
				t.Fatalf("suspended backup counted: age %v", m.Value)
			}
			return
		}
	}
	t.Fatal("missing backup age")
}

// A named timezone is honored without zoneinfo on disk, and one that cannot be
// loaded yields no answer instead of a UTC projection.
func TestNextRunTimezone(t *testing.T) {
	job := cj("app", "report", "0 8 * * *", false)
	tz := "Asia/Tokyo"
	job.Spec.TimeZone = &tz
	if got := projectNextRun(job, at("2026-09-14T09:00:00Z")); got != "2026-09-14T23:00:00Z" {
		t.Errorf("08:00 Tokyo after 09:00Z = %q, want 2026-09-14T23:00:00Z", got)
	}
	bogus := "Mars/Olympus_Mons"
	job.Spec.TimeZone = &bogus
	if got := projectNextRun(job, at("2026-09-14T09:00:00Z")); got != "" {
		t.Errorf("unknown timezone projected %q; it must yield no answer", got)
	}
}

func TestCronReportInputsHonorExclusions(t *testing.T) {
	c := NewCollector("prod-cluster")
	c.SetExcludedNamespaces([]string{"sandbox"})
	jobs := inScope(c, []CronJob{cj("app", "a", "@daily", false), cj("sandbox", "b", "@daily", false)},
		func(x CronJob) string { return x.Metadata.Namespace })
	if len(jobs) != 1 || jobs[0].Metadata.Namespace != "app" {
		t.Fatalf("got %+v", jobs)
	}
}
