package k8s

import "testing"

func TestParseImageRef(t *testing.T) {
	cases := []struct {
		image, repo, tag, digest string
	}{
		{"nginx", "nginx", "latest", ""},
		{"nginx:1.27", "nginx", "1.27", ""},
		{"ghcr.io/cloudnative-pg/cloudnative-pg:1.24.0", "ghcr.io/cloudnative-pg/cloudnative-pg", "1.24.0", ""},
		{"ghcr.io/example/cloudnativepg-timescale:18-ts2.24.0", "ghcr.io/example/cloudnativepg-timescale", "18-ts2.24.0", ""},
		// A registry port must not be mistaken for a tag.
		{"reg.example.com:5000/app", "reg.example.com:5000/app", "latest", ""},
		{"reg.example.com:5000/app:v2", "reg.example.com:5000/app", "v2", ""},
		// Digest-pinned.
		{"app@sha256:abc123", "app", "", "sha256:abc123"},
		{"reg:5000/app:v2@sha256:def", "reg:5000/app", "v2", "sha256:def"},
	}
	for _, c := range cases {
		repo, tag, digest := parseImageRef(c.image)
		if repo != c.repo || tag != c.tag || digest != c.digest {
			t.Errorf("parseImageRef(%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.image, repo, tag, digest, c.repo, c.tag, c.digest)
		}
	}
}

func TestJobHealth(t *testing.T) {
	failed := Job{Status: JobStatus{Failed: 1, Conditions: []JobCondition{
		{Type: "Failed", Status: "True", Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"}}}}
	if hs := jobHealth(failed); hs.healthy || hs.reason != "JobFailed" {
		t.Fatalf("failed job should be unhealthy JobFailed, got %+v", hs)
	}

	complete := Job{Status: JobStatus{Succeeded: 1, Conditions: []JobCondition{{Type: "Complete", Status: "True"}}}}
	if hs := jobHealth(complete); !hs.healthy {
		t.Fatalf("complete job should be healthy, got %+v", hs)
	}

	active := Job{Status: JobStatus{Active: 1}}
	if hs := jobHealth(active); !hs.healthy {
		t.Fatalf("active job should be healthy, got %+v", hs)
	}
}

func TestJobOwnerRollsUpToCronJob(t *testing.T) {
	j := Job{Metadata: ObjectMeta{Namespace: "data", Name: "db-backup-29012345",
		OwnerReferences: []OwnerReference{{Kind: "CronJob", Name: "db-backup", Controller: boolPtr(true)}}}}
	if got := jobOwner(j); got != "CronJob/db-backup" {
		t.Fatalf("jobOwner = %q, want CronJob/db-backup", got)
	}
	// A standalone Job has no controller owner.
	if got := jobOwner(Job{Metadata: ObjectMeta{Name: "oneoff"}}); got != "" {
		t.Fatalf("standalone jobOwner = %q, want empty", got)
	}
}
