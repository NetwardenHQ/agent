package container

import "testing"

func find(t *testing.T, inv []imageEntry, ref string) imageEntry {
	t.Helper()
	for _, e := range inv {
		if e.Reference == ref {
			return e
		}
	}
	t.Fatalf("image %q not in inventory %+v", ref, inv)
	return imageEntry{}
}

// Twenty replicas of one image report as one entry with a count.
func TestBuildImageInventory_DeduplicatesByDigest(t *testing.T) {
	var containers []Container
	for i := 0; i < 20; i++ {
		containers = append(containers, Container{
			ID: string(rune('a' + i)), Image: "nginx:1.27",
			ImageID: "sha256:aaa", Status: "running",
		})
	}
	inv := buildImageInventory(containers)
	if len(inv) != 1 {
		t.Fatalf("expected 1 image, got %d", len(inv))
	}
	if inv[0].RunningCount != 20 || inv[0].TotalCount != 20 {
		t.Errorf("counts wrong: %+v", inv[0])
	}
	if inv[0].Digest != "sha256:aaa" {
		t.Errorf("digest lost: %+v", inv[0])
	}
}

// Two tags resolving to the same digest are one image; distinct digests are
// distinct images even under the same tag (":latest" moved).
func TestBuildImageInventory_DigestIsIdentity(t *testing.T) {
	inv := buildImageInventory([]Container{
		{ID: "1", Image: "app:latest", ImageID: "sha256:v1", Status: "running"},
		{ID: "2", Image: "app:1.0", ImageID: "sha256:v1", Status: "running"},   // same digest, other tag
		{ID: "3", Image: "app:latest", ImageID: "sha256:v2", Status: "exited"}, // latest moved
	})
	if len(inv) != 2 {
		t.Fatalf("expected 2 distinct digests, got %d: %+v", len(inv), inv)
	}
	// The v1 digest is used by two containers under two tags.
	var v1 imageEntry
	for _, e := range inv {
		if e.Digest == "sha256:v1" {
			v1 = e
		}
	}
	if v1.TotalCount != 2 || v1.RunningCount != 2 {
		t.Errorf("v1 counts wrong: %+v", v1)
	}
}

// Without an ImageID the reference is the key, so digest-less images do not
// collapse into one bucket.
func TestBuildImageInventory_NoDigestKeysOnReference(t *testing.T) {
	inv := buildImageInventory([]Container{
		{ID: "1", Image: "redis:7", Status: "running"},
		{ID: "2", Image: "postgres:16", Status: "running"},
		{ID: "3", Image: "redis:7", Status: "running"},
	})
	if len(inv) != 2 {
		t.Fatalf("expected 2 images keyed by reference, got %d: %+v", len(inv), inv)
	}
	if r := find(t, inv, "redis:7"); r.TotalCount != 2 {
		t.Errorf("redis count wrong: %+v", r)
	}
}

// Running images sort ahead of stopped ones so the most relevant appear first.
func TestBuildImageInventory_Ordering(t *testing.T) {
	inv := buildImageInventory([]Container{
		{ID: "1", Image: "zzz:1", ImageID: "sha256:z", Status: "running"},
		{ID: "2", Image: "aaa:1", ImageID: "sha256:a", Status: "exited"},
	})
	if inv[0].Reference != "zzz:1" {
		t.Errorf("running image should sort first, got %+v", inv)
	}
}

func TestBuildImageInventory_SkipsEmpty(t *testing.T) {
	inv := buildImageInventory([]Container{
		{ID: "1", Status: "running"}, // no image and no id
		{ID: "2", Image: "busybox", ImageID: "sha256:b", Status: "running"},
	})
	if len(inv) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(inv), inv)
	}
}

func TestBuildImageInventory_Empty(t *testing.T) {
	if inv := buildImageInventory(nil); len(inv) != 0 {
		t.Errorf("nil input should yield empty inventory, got %+v", inv)
	}
}
