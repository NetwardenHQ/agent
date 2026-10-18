package k8s

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Client is a minimal Kubernetes API client speaking plain HTTPS and JSON. The
// REST surface the collector needs (list and watch on a handful of resources)
// is small and stable, so it avoids the large k8s.io/client-go dependency.
type Client struct {
	cfg    Config
	base   string
	list   *http.Client // bounded timeout, for list/get
	stream *http.Client // no overall timeout, for long-lived watches
}

// listTimeout bounds a single list/get. Watches are unbounded (governed by the
// request context) because a healthy watch stays open for minutes.
const listTimeout = 30 * time.Second

// maxListBytes caps a single list response so a pathological cluster cannot
// exhaust the agent's memory. Watches stream event-by-event and are not
// subject to this.
const maxListBytes = 32 << 20 // 32 MiB

// Watch lifetime. Every watch asks the API server to end it after a random
// 5-10 minutes (`timeoutSeconds`, the same range client-go uses), and the
// request context expires a little later as a backstop. Without both, a
// connection that dies silently (an expired NAT entry, a network blip) leaves
// Decode blocked forever and the store stale until restart. Ending watches
// deliberately turns that into a routine re-watch from the last
// resourceVersion.
var (
	watchTimeoutMin   = 5 * time.Minute
	watchTimeoutMax   = 10 * time.Minute
	watchTimeoutGrace = 30 * time.Second
)

// watchTimeout picks a watch's server-side lifetime. It is randomized so the
// reflectors do not all re-watch at the same instant.
func watchTimeout() time.Duration {
	return watchTimeoutMin + rand.N(watchTimeoutMax-watchTimeoutMin)
}

// NewClient builds a client from cfg, loading the cluster CA into a dedicated
// trust pool. It does not contact the API server.
func NewClient(cfg Config) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.CAPath != "" {
		caPEM, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("reading cluster CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("cluster CA at %s contains no usable certificates", cfg.CAPath)
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &Client{
		cfg:    cfg,
		base:   strings.TrimRight(cfg.Host, "/"),
		list:   &http.Client{Timeout: listTimeout, Transport: transport},
		stream: &http.Client{Transport: transport},
	}, nil
}

// token reads the bearer token fresh from disk (see Config.TokenPath): the
// projected token rotates, so the current file is always the source of truth.
func (c *Client) token() (string, error) {
	b, err := os.ReadFile(c.cfg.TokenPath)
	if err != nil {
		return "", fmt.Errorf("reading service-account token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Client) newRequest(ctx context.Context, path string, query url.Values) (*http.Request, error) {
	tok, err := c.token()
	if err != nil {
		return nil, err
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Get performs a GET and returns the response body, failing on any non-2xx.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	req, err := c.newRequest(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.list.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Reading one byte past the cap distinguishes "at the limit" from "over
	// it", so an oversized body is reported as such rather than as a JSON
	// decode error.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, apiError(path, resp.StatusCode, body)
	}
	if len(body) > maxListBytes {
		return nil, fmt.Errorf("k8s API %s: response too large (over %d MiB)", path, maxListBytes>>20)
	}
	return body, nil
}

// List GETs path and decodes the JSON body into out.
func (c *Client) List(ctx context.Context, path string, out any) error {
	body, err := c.Get(ctx, path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding %s: %w", path, err)
	}
	return nil
}

// Watch opens a streaming watch on path from resourceVersion. The returned
// Stream yields one WatchEvent per Next call until the context is canceled,
// the server closes the stream, or an error occurs. The caller must close it.
func (c *Client) Watch(ctx context.Context, path, resourceVersion string) (*Stream, error) {
	q := url.Values{}
	q.Set("watch", "1")
	if resourceVersion != "" {
		q.Set("resourceVersion", resourceVersion)
	}
	// Bookmarks let the server periodically advance the resource version with
	// no real change. The reflector resumes from the newest version it has
	// seen, so on a quiet resource bookmarks are what keep that version recent
	// enough not to be rejected as too old.
	q.Set("allowWatchBookmarks", "true")

	lifetime := watchTimeout()
	q.Set("timeoutSeconds", strconv.Itoa(int(lifetime.Seconds())))
	ctx, cancel := context.WithTimeout(ctx, lifetime+watchTimeoutGrace)

	req, err := c.newRequest(ctx, path, q)
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		cancel()
		return nil, apiError(path, resp.StatusCode, body)
	}
	return &Stream{resp: resp, dec: json.NewDecoder(bufio.NewReader(resp.Body)), cancel: cancel}, nil
}

// Stream is an open watch connection yielding decoded events.
type Stream struct {
	resp   *http.Response
	dec    *json.Decoder
	cancel context.CancelFunc
}

// Next decodes the next watch event. It blocks until an event arrives, the
// stream ends (io.EOF), or the context behind the request is canceled.
func (s *Stream) Next() (WatchEvent, error) {
	var ev WatchEvent
	err := s.dec.Decode(&ev)
	return ev, err
}

// Close terminates the watch connection.
func (s *Stream) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.resp != nil && s.resp.Body != nil {
		return s.resp.Body.Close()
	}
	return nil
}

// ServerVersion fetches the API server's reported gitVersion.
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	var v VersionInfo
	if err := c.List(ctx, "/version", &v); err != nil {
		return "", err
	}
	return v.GitVersion, nil
}

// apiStatusError is a non-2xx answer from the API server. The reflector treats
// it as "retrying will not help" and re-lists, whereas a transport error is
// retried.
type apiStatusError struct {
	path   string
	status int
	detail string
}

func (e *apiStatusError) Error() string {
	return fmt.Sprintf("k8s API %s: %s", e.path, e.detail)
}

// maxErrorSnippet bounds how much of a non-Status error body reaches the logs.
const maxErrorSnippet = 256

// apiError renders a compact error from a non-2xx API response, surfacing the
// Status message Kubernetes returns as JSON when it can be parsed, and
// otherwise a short excerpt of whatever came back (a proxy's HTML error page,
// a plain-text message), which is usually the only clue to what answered.
func apiError(path string, status int, body []byte) error {
	var s struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if json.Unmarshal(body, &s) == nil && s.Message != "" {
		return &apiStatusError{path: path, status: status,
			detail: fmt.Sprintf("%d %s (%s)", status, s.Reason, s.Message)}
	}
	detail := fmt.Sprintf("HTTP %d", status)
	if snippet := errorSnippet(body); snippet != "" {
		detail += ": " + snippet
	}
	return &apiStatusError{path: path, status: status, detail: detail}
}

// errorSnippet returns the start of body as one printable line.
func errorSnippet(body []byte) string {
	if len(body) > maxErrorSnippet {
		body = body[:maxErrorSnippet]
	}
	s := strings.ToValidUTF8(string(body), "")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}
