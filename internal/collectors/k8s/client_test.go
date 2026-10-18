package k8s

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestBuildAuthority(t *testing.T) {
	cases := []struct {
		host, port, want string
	}{
		{"10.0.0.1", "443", "10.0.0.1:443"},
		{"kubernetes.default.svc", "443", "kubernetes.default.svc:443"},
		{"fd00::1", "6443", "[fd00::1]:6443"}, // IPv6 literal must be bracketed
	}
	for _, c := range cases {
		if got := buildAuthority(c.host, c.port); got != c.want {
			t.Errorf("buildAuthority(%q,%q) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestAPIError(t *testing.T) {
	// A Kubernetes Status body surfaces its message and reason.
	err := apiError("/api/v1/pods", 403,
		[]byte(`{"kind":"Status","message":"forbidden: pods is forbidden","reason":"Forbidden"}`))
	if err == nil || !strings.Contains(err.Error(), "forbidden: pods is forbidden") {
		t.Fatalf("expected Status message in error, got %v", err)
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("expected reason in error, got %v", err)
	}

	// A non-JSON body falls back to the plain HTTP status.
	err = apiError("/version", 500, []byte("upstream boom"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("expected HTTP 500 fallback, got %v", err)
	}
}

func TestNewClientRejectsBadCA(t *testing.T) {
	// A CA path that exists but holds no certs must fail fast, not silently
	// build a client that trusts nothing.
	bad := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(Config{Host: "https://x:443", CAPath: bad}); err == nil {
		t.Fatal("expected error for CA file with no usable certificates")
	}
}

func TestEnabledFalseWithoutCluster(t *testing.T) {
	// No WithConfig and (in the test env) no in-cluster mount → inert.
	c := NewCollector("test-host")
	if c.Enabled() {
		t.Skip("running inside a cluster; detection correctly returned enabled")
	}
	if got, err := c.Collect(t.Context()); err != nil || got != nil {
		t.Fatalf("disabled collector should no-op, got metrics=%v err=%v", got, err)
	}
}

// A body past maxListBytes is reported as too large, not truncated into a
// confusing JSON decode error; a non-Status error body is quoted, bounded.
func TestClientGetBoundsAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write(make([]byte, maxListBytes+1))
		case "/proxy":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "<html>upstream\nconnect error "+strings.Repeat("x", 4096)+"</html>")
		}
	}))
	defer srv.Close()
	c := testClient(t, srv)

	if _, err := c.Get(t.Context(), "/big"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want a too-large error, got %v", err)
	}
	_, err := c.Get(t.Context(), "/proxy")
	if err == nil || !strings.Contains(err.Error(), "HTTP 502: <html>upstream connect error") {
		t.Fatalf("want the body's first line in the error, got %v", err)
	}
	if len(err.Error()) > maxErrorSnippet+64 {
		t.Fatalf("error not bounded: %d bytes", len(err.Error()))
	}
}
