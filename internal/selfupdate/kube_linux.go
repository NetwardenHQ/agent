//go:build linux

package selfupdate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

	// updateAnnotation records on the pod template which release a
	// replacement was for, so `kubectl describe` says why the pod changed.
	updateAnnotation = "netwarden.com/update-to"
	// restartAnnotation is the one `kubectl rollout restart` sets.
	restartAnnotation = "kubectl.kubernetes.io/restartedAt"
)

var (
	// errNotPermitted: the agent's ServiceAccount may not patch its
	// Deployment (an install from before the permission was granted).
	errNotPermitted = errors.New("the agent's ServiceAccount may not restart its Deployment")
	// errWouldNotUpdate: a new pod would run the same release.
	errWouldNotUpdate = errors.New("a new pod would not run the new release")
)

// kubeAPI is the little of the Kubernetes API an update needs, as the pod's
// own ServiceAccount.
type kubeAPI struct {
	base      string
	token     string
	namespace string
	pod       string
	client    *http.Client
}

// inClusterAPI reads the ServiceAccount the kubelet mounted into the pod.
func inClusterAPI() (*kubeAPI, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not in a cluster")
	}
	token, err := os.ReadFile(serviceAccountDir + "/token")
	if err != nil {
		return nil, err
	}
	namespace, err := os.ReadFile(serviceAccountDir + "/namespace")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("unreadable cluster CA")
	}
	pod, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	return &kubeAPI{
		base:      "https://" + net.JoinHostPort(host, port),
		token:     strings.TrimSpace(string(token)),
		namespace: strings.TrimSpace(string(namespace)),
		pod:       pod,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// do sends one request and decodes a JSON reply into out when it is non-nil.
func (k *kubeAPI) do(ctx context.Context, method, path, contentType string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%s %s: %w", method, path, errNotPermitted)
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

type objectMeta struct {
	Metadata struct {
		OwnerReferences []struct {
			Kind       string `json:"kind"`
			Name       string `json:"name"`
			Controller bool   `json:"controller"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
}

func (o objectMeta) controller(kind string) (string, bool) {
	for _, ref := range o.Metadata.OwnerReferences {
		if ref.Controller && ref.Kind == kind {
			return ref.Name, true
		}
	}
	return "", false
}

// ownDeployment finds the Deployment this pod belongs to: pod, then the
// ReplicaSet that controls it, then the Deployment that controls that.
func (k *kubeAPI) ownDeployment(ctx context.Context) (string, error) {
	var pod objectMeta
	if err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+k.namespace+"/pods/"+k.pod, "", nil, &pod); err != nil {
		return "", err
	}
	rs, ok := pod.controller("ReplicaSet")
	if !ok {
		return "", errors.New("this pod is not managed by a Deployment")
	}
	var set objectMeta
	if err := k.do(ctx, http.MethodGet, "/apis/apps/v1/namespaces/"+k.namespace+"/replicasets/"+rs, "", nil, &set); err != nil {
		return "", err
	}
	dep, ok := set.controller("Deployment")
	if !ok {
		return "", errors.New("this pod's ReplicaSet is not managed by a Deployment")
	}
	return dep, nil
}

// pullsRelease reports whether a new pod of a container with this image and
// pull policy would run version: an image tagged with it, or the latest tag
// pulled afresh on every start. A digest, or another version's tag, would
// bring back what is running now.
func pullsRelease(image, policy, version string) bool {
	if strings.Contains(image, "@") {
		return false
	}
	tag := "latest"
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		tag = image[i+1:]
	}
	if tag == version || tag == "v"+version {
		return true
	}
	return tag == "latest" && policy == "Always"
}

// replacePod asks Kubernetes to replace this pod, the way `kubectl rollout
// restart` does, after checking that the new pod would run version.
func (k *kubeAPI) replacePod(ctx context.Context, version string, now time.Time) error {
	dep, err := k.ownDeployment(ctx)
	if err != nil {
		return err
	}
	path := "/apis/apps/v1/namespaces/" + k.namespace + "/deployments/" + dep
	var spec struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name            string `json:"name"`
						Image           string `json:"image"`
						ImagePullPolicy string `json:"imagePullPolicy"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := k.do(ctx, http.MethodGet, path, "", nil, &spec); err != nil {
		return err
	}
	containers := spec.Spec.Template.Spec.Containers
	if len(containers) == 0 {
		return errors.New("the Deployment has no containers")
	}
	c := containers[0]
	for _, candidate := range containers {
		if candidate.Name == "agent" || strings.Contains(candidate.Image, "netwarden/agent") {
			c = candidate
			break
		}
	}
	if !pullsRelease(c.Image, c.ImagePullPolicy, version) {
		return fmt.Errorf("%w: Deployment %s runs %s with imagePullPolicy %s", errWouldNotUpdate, dep, c.Image, c.ImagePullPolicy)
	}
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
		"annotations": map[string]string{
			restartAnnotation: now.UTC().Format(time.RFC3339),
			updateAnnotation:  version,
		},
	}}}})
	if err != nil {
		return err
	}
	return k.do(ctx, http.MethodPatch, path, "application/strategic-merge-patch+json", patch, nil)
}
