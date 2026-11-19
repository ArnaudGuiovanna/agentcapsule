package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

type client struct {
	http       *http.Client
	connection connection
}

func newClient(c connection) (*client, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CA != "" {
		b, err := os.ReadFile(c.CA)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid context CA")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &client{&http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, c}, nil
}

type apiError struct {
	Status    int    `json:"status"`
	Code      string `json:"code"`
	RequestID string `json:"request_id,omitempty"`
	Quota     string `json:"quota,omitempty"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("HTTP %d %s (request %s)", e.Status, e.Code, e.RequestID)
}

type reply struct {
	Data       json.RawMessage
	RequestID  string
	RetryAfter string
}

var codePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,100}$`)

func safeCode(s string) string {
	if codePattern.MatchString(s) {
		return s
	}
	return ""
}
func validRoute(route string) bool {
	u, err := url.ParseRequestURI(route)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/v1/") || strings.ContainsAny(route, "#\\\r\n") || path.Clean(u.Path) != u.Path {
		return false
	}
	return !strings.Contains(strings.ToLower(u.EscapedPath()), "%2f")
}
func (c *client) request(ctx context.Context, method, route, key, token string, body []byte) (reply, error) {
	if !validRoute(route) {
		return reply{}, errors.New("expected a canonical /v1/ API path")
	}
	var payload io.Reader
	if body != nil {
		payload = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.connection.URL, "/")+route, payload)
	if err != nil {
		return reply{}, errors.New("invalid HTTP request")
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return reply{}, ctx.Err()
		}
		// url.Error echoes the full URL, which may contain a private download link.
		var cause *url.Error
		if errors.As(err, &cause) {
			err = cause.Err
		}
		return reply{}, fmt.Errorf("API transport: %w", err)
	}
	defer res.Body.Close()
	id := safeCode(res.Header.Get("X-Request-ID"))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var problem apiError
		raw, _ := readBounded(res.Body, 16384)
		_ = json.Unmarshal(raw, &problem)
		problem.Code = safeCode(problem.Code)
		if problem.Code == "" {
			problem.Code = "request_failed"
		}
		problem.Quota = safeCode(problem.Quota)
		problem.Status = res.StatusCode
		problem.RequestID = id
		return reply{}, &problem
	}
	raw, err := readBounded(res.Body, 32<<20)
	if err != nil {
		return reply{}, err
	}
	if len(raw) == 0 {
		raw = []byte("null")
	}
	if !json.Valid(raw) {
		return reply{}, errors.New("expected a JSON API response")
	}
	return reply{raw, id, res.Header.Get("Retry-After")}, nil
}
func (c *client) compatible(ctx context.Context) error {
	r, err := c.request(ctx, "GET", "/v1/version", "", "", nil)
	if err != nil {
		return err
	}
	var v struct {
		Major    int `json:"api_major"`
		Protocol int `json:"cli_protocol"`
	}
	if json.Unmarshal(r.Data, &v) != nil || v.Major != 1 || v.Protocol != 1 {
		return errors.New("incompatible API or CLI protocol (expected 1)")
	}
	return nil
}
func (c *client) verifyToken(ctx context.Context, token string) (reply, error) {
	if token == "" {
		return reply{}, errors.New("log in to this context first")
	}
	route := "/v1/platform/session"
	if c.connection.Kind == "organization" {
		route = "/v1/organizations/current"
	}
	r, err := c.request(ctx, "GET", route, "", token, nil)
	if err != nil {
		return reply{}, err
	}
	if c.connection.Kind == "organization" {
		var who struct {
			Organization struct {
				ID string `json:"id"`
			} `json:"organization"`
		}
		if json.Unmarshal(r.Data, &who) != nil || who.Organization.ID != c.connection.Organization {
			return reply{}, errors.New("credential belongs to a different organization")
		}
	}
	return r, nil
}
