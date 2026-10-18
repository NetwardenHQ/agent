package k8s

import (
	"os"
	"strings"
)

// Standard in-cluster ServiceAccount mount paths. The kubelet projects a
// bound, rotating token, the cluster CA bundle, and the pod's own namespace
// here for every pod that has a ServiceAccount (every pod unless it opts out),
// which lets the collector authenticate to its own API server without a
// kubeconfig.
const (
	saDir            = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultTokenPath = saDir + "/token"
	defaultCAPath    = saDir + "/ca.crt"
	defaultNSPath    = saDir + "/namespace"
)

// Config locates the API server and the credentials to reach it.
type Config struct {
	// Host is the API server base URL, e.g. https://10.0.0.1:443.
	Host string

	// TokenPath is the file holding the bearer token. It is read on every
	// request (see Client.token) because the projected token rotates: bound
	// ServiceAccount tokens live for about an hour and the kubelet rewrites
	// the file, so a cached copy would eventually go stale.
	TokenPath string

	// CAPath is the cluster CA bundle used to verify the API server certificate.
	CAPath string

	// Namespace is the pod's own namespace (informational; used in logs).
	Namespace string
}

// inClusterConfig builds a Config from the standard ServiceAccount mount and
// the KUBERNETES_SERVICE_* environment the kubelet injects. It returns
// (nil, false) when any required piece is missing, which is the normal case
// for a host agent outside Kubernetes and keeps the collector inert.
func inClusterConfig() (*Config, bool) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, false
	}

	// The token file must exist and be non-empty; without it there is no way
	// to authenticate, so treat its absence as "not in cluster".
	if fi, err := os.Stat(defaultTokenPath); err != nil || fi.Size() == 0 {
		return nil, false
	}

	ns := ""
	if b, err := os.ReadFile(defaultNSPath); err == nil {
		ns = strings.TrimSpace(string(b))
	}

	return &Config{
		Host:      "https://" + buildAuthority(host, port),
		TokenPath: defaultTokenPath,
		CAPath:    defaultCAPath,
		Namespace: ns,
	}, true
}

// buildAuthority joins host and port into a URL authority, bracketing an IPv6
// literal as RFC 3986 requires.
func buildAuthority(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
