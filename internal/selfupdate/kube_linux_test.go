//go:build linux

package selfupdate

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// apiServer stands in for the Kubernetes API: one pod owned by a ReplicaSet
// owned by a Deployment, and a record of the patches it receives.
type apiServer struct {
	mu         sync.Mutex
	image      string
	pullPolicy string
	patchCode  int
	patches    []string
	podOwner   string
}

func (s *apiServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer sa-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/netwarden/pods/netwarden-agent-5f9c7-abcde":
		owner := s.podOwner
		if owner == "" {
			owner = `{"kind":"ReplicaSet","name":"netwarden-agent-5f9c7","controller":true}`
		}
		io.WriteString(w, `{"metadata":{"ownerReferences":[`+owner+`]}}`)
	case r.Method == http.MethodGet && r.URL.Path == "/apis/apps/v1/namespaces/netwarden/replicasets/netwarden-agent-5f9c7":
		io.WriteString(w, `{"metadata":{"ownerReferences":[{"kind":"Deployment","name":"netwarden-agent","controller":true}]}}`)
	case r.Method == http.MethodGet && r.URL.Path == "/apis/apps/v1/namespaces/netwarden/deployments/netwarden-agent":
		dep := map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []map[string]any{{"name": "agent", "image": s.image, "imagePullPolicy": s.pullPolicy}},
		}}}}
		json.NewEncoder(w).Encode(dep)
	case r.Method == http.MethodPatch && r.URL.Path == "/apis/apps/v1/namespaces/netwarden/deployments/netwarden-agent":
		body, _ := io.ReadAll(r.Body)
		s.patches = append(s.patches, r.Header.Get("Content-Type")+" "+string(body))
		if s.patchCode != 0 {
			w.WriteHeader(s.patchCode)
			io.WriteString(w, `{"kind":"Status","reason":"Forbidden"}`)
			return
		}
		io.WriteString(w, `{}`)
	default:
		http.NotFound(w, r)
	}
}

func newTestKube(t *testing.T, s *apiServer) *kubeAPI {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(s.handler))
	t.Cleanup(srv.Close)
	return &kubeAPI{base: srv.URL, token: "sa-token", namespace: "netwarden", pod: "netwarden-agent-5f9c7-abcde", client: srv.Client()}
}

func TestOwnDeploymentIsFoundThroughTheReplicaSet(t *testing.T) {
	k := newTestKube(t, &apiServer{image: "reg.example/netwarden/agent:latest", pullPolicy: "Always"})
	name, err := k.ownDeployment(t.Context())
	if err != nil || name != "netwarden-agent" {
		t.Fatalf("deployment %q, err %v", name, err)
	}
}

func TestAPodNotOwnedByADeploymentIsNotReplaced(t *testing.T) {
	k := newTestKube(t, &apiServer{podOwner: `{"kind":"DaemonSet","name":"netwarden-agent","controller":true}`})
	if _, err := k.ownDeployment(t.Context()); err == nil {
		t.Fatal("a pod owned by a DaemonSet was taken for a Deployment's")
	}
}

func TestReplacingThePodPatchesOnlyThePodTemplate(t *testing.T) {
	s := &apiServer{image: "reg.example/netwarden/agent:latest", pullPolicy: "Always"}
	k := newTestKube(t, s)
	at := time.Date(2026, 11, 12, 1, 14, 0, 0, time.UTC)
	if err := k.replacePod(t.Context(), "3.6.0", at); err != nil {
		t.Fatal(err)
	}
	if len(s.patches) != 1 {
		t.Fatalf("patches: %v", s.patches)
	}
	got := s.patches[0]
	if !strings.HasPrefix(got, "application/strategic-merge-patch+json ") {
		t.Fatalf("content type: %s", got)
	}
	for _, want := range []string{`"kubectl.kubernetes.io/restartedAt":"2026-11-12T01:14:00Z"`, `"netwarden.com/update-to":"3.6.0"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("patch %s lacks %s", got, want)
		}
	}
	// Nothing outside the pod template's annotations is touched.
	var patch map[string]any
	json.Unmarshal([]byte(strings.TrimPrefix(got, "application/strategic-merge-patch+json ")), &patch)
	spec := patch["spec"].(map[string]any)
	if len(patch) != 1 || len(spec) != 1 {
		t.Fatalf("the patch reaches beyond the pod template: %v", patch)
	}
}

// A new pod only helps when it will pull the new release. A Deployment pinned
// to another version, or one that may reuse a cached image, would come back
// as the same version: that is not an update, and doing it every night is a
// pod churning for nothing.
func TestAPodIsReplacedOnlyWhenTheNewOneGetsTheRelease(t *testing.T) {
	for _, tc := range []struct {
		image, policy string
		ok            bool
	}{
		{"reg.example/netwarden/agent:latest", "Always", true},
		{"reg.example/netwarden/agent", "Always", true},
		{"reg.example/netwarden/agent:3.6.0", "IfNotPresent", true},
		{"reg.example:5000/netwarden/agent:3.6.0", "Always", true},
		{"reg.example/netwarden/agent:3.5.0", "Always", false},
		{"reg.example/netwarden/agent:latest", "IfNotPresent", false},
		{"reg.example/netwarden/agent@sha256:26167fee", "Always", false},
		{"reg.example:5000/netwarden/agent", "IfNotPresent", false},
	} {
		s := &apiServer{image: tc.image, pullPolicy: tc.policy}
		k := newTestKube(t, s)
		err := k.replacePod(t.Context(), "3.6.0", time.Now())
		if tc.ok != (err == nil) {
			t.Errorf("%s (%s): err %v, want ok=%v", tc.image, tc.policy, err, tc.ok)
		}
		if !tc.ok && !errors.Is(err, errWouldNotUpdate) {
			t.Errorf("%s (%s): %v is not errWouldNotUpdate", tc.image, tc.policy, err)
		}
		if !tc.ok && len(s.patches) != 0 {
			t.Errorf("%s (%s): patched anyway", tc.image, tc.policy)
		}
	}
}

func TestAForbiddenPatchIsReportedAsSuch(t *testing.T) {
	s := &apiServer{image: "reg.example/netwarden/agent:latest", pullPolicy: "Always", patchCode: http.StatusForbidden}
	k := newTestKube(t, s)
	err := k.replacePod(t.Context(), "3.6.0", time.Now())
	if !errors.Is(err, errNotPermitted) {
		t.Fatalf("a 403 was reported as %v", err)
	}
}
