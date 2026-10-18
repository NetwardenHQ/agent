package k8s

import "encoding/json"

// Minimal typed views of the metadata and envelopes shared by every Kubernetes
// API object the collector reads; the per-kind types are in apiobjects.go. Only
// the fields actually consumed are declared; the API server sends much more and
// encoding/json ignores the rest.

// TypeMeta is the apiVersion/kind envelope present on every object.
type TypeMeta struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
}

// ObjectMeta is the metadata common to all namespaced and cluster objects.
type ObjectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	Generation        int64             `json:"generation,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	DeletionTimestamp *string           `json:"deletionTimestamp,omitempty"`
}

// OwnerReference points an object at the controller that manages it. It is how
// a finding on an ephemeral pod is rolled up to its Deployment, Job, and so on.
type OwnerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller,omitempty"`
}

// ListMeta carries the resourceVersion a watch resumes from after a list.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion"`
}

// WatchEvent is one event in a watch stream (ADDED, MODIFIED, DELETED,
// BOOKMARK or ERROR), with the raw object for the consumer to decode into the
// concrete type it expects.
type WatchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// Watch event type constants.
const (
	WatchAdded    = "ADDED"
	WatchModified = "MODIFIED"
	WatchDeleted  = "DELETED"
	WatchBookmark = "BOOKMARK"
	WatchError    = "ERROR"
)

// VersionInfo is the API server's /version response (subset).
type VersionInfo struct {
	GitVersion string `json:"gitVersion"`
	Platform   string `json:"platform"`
}
