package ociregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ociManifestType = "application/vnd.oci.image.manifest.v1+json"
	maxManifest     = 64 << 10
	maxToken        = 64 << 10
)

// client talks to one approved registry. It has its own transport so the
// address policy of that rule applies to every connection, including blob
// redirects and token requests. Environment proxies are ignored.
type client struct {
	rule  Rule
	http  *http.Client
	mu    sync.Mutex
	token map[string]string // repository -> bearer token
}

func newClient(rule Rule, timeout time.Duration) *client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrPolicy
		}
		ip := net.ParseIP(host)
		if ip == nil || (!rule.Local && !publicIP(ip)) {
			return fmt.Errorf("%w: refusing to connect to a non-public address", ErrPolicy)
		}
		return nil
	}}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	c := &client{rule: rule, token: map[string]string{}}
	c.http = &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("%w: too many redirects", ErrPolicy)
		}
		if !c.allowedURL(req.URL, c.rule.BlobHosts) {
			return fmt.Errorf("%w: redirect to an unapproved host", ErrPolicy)
		}
		return nil
	}}
	return c
}

// allowedURL: HTTPS (HTTP only for a local registry) to the registry itself or
// one of the extra hosts.
func (c *client) allowedURL(u *url.URL, extra []string) bool {
	if u.User != nil || !(u.Scheme == "https" || c.rule.Local && u.Scheme == "http") {
		return false
	}
	host := strings.ToLower(u.Host)
	if host == c.rule.Host {
		return true
	}
	for _, h := range extra {
		if host == h {
			return true
		}
	}
	return false
}

func (c *client) base() string {
	if c.rule.Local {
		return "http://" + c.rule.Host
	}
	return "https://" + c.rule.Host
}

// do sends a registry request, answering one bearer or basic challenge.
func (c *client) do(ctx context.Context, repo, scope string, build func() (*http.Request, error)) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := build()
		if err != nil {
			return nil, err
		}
		req = req.WithContext(ctx)
		c.mu.Lock()
		token := c.token[repo]
		c.mu.Unlock()
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else if c.rule.Username != "" {
			req.SetBasicAuth(c.rule.Username, c.rule.Password)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if errors.Is(err, ErrPolicy) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %s", ErrUnavailable, redact(err))
		}
		if resp.StatusCode != http.StatusUnauthorized || attempt == 1 {
			return resp, nil
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		drain(resp)
		if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
			return nil, fmt.Errorf("%w: registry requires authentication", ErrUnavailable)
		}
		if err = c.fetchToken(ctx, repo, scope, challenge); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: authentication loop", ErrUnavailable)
}

func (c *client) fetchToken(ctx context.Context, repo, scope, challenge string) error {
	params := parseChallenge(challenge[len("bearer "):])
	realm, err := url.Parse(params["realm"])
	if err != nil || !c.allowedURL(realm, c.rule.TokenHosts) {
		return fmt.Errorf("%w: token realm not approved", ErrPolicy)
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return ErrPolicy
	}
	if c.rule.Username != "" {
		req.SetBasicAuth(c.rule.Username, c.rule.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrPolicy) {
			return err
		}
		return fmt.Errorf("%w: token request failed", ErrUnavailable)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: token request answered %d", ErrUnavailable, resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxToken)).Decode(&body); err != nil {
		return fmt.Errorf("%w: token response", ErrUnavailable)
	}
	token := body.Token
	if token == "" {
		token = body.AccessToken
	}
	if token == "" || strings.ContainsAny(token, "\r\n ") {
		return fmt.Errorf("%w: empty token", ErrUnavailable)
	}
	c.mu.Lock()
	c.token[repo] = token
	c.mu.Unlock()
	return nil
}

// parseChallenge reads key="value" pairs of a WWW-Authenticate header.
func parseChallenge(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ,")
		k, rest, ok := strings.Cut(s, "=")
		if !ok {
			break
		}
		var v string
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end < 0 {
				break
			}
			v, s = rest[1:end+1], rest[end+2:]
		} else {
			v, s, _ = strings.Cut(rest, ",")
		}
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// redact keeps a transport error useful without echoing URLs or credentials.
func redact(err error) string {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Op + ": " + redactInner(u.Err)
	}
	return redactInner(err)
}

func redactInner(err error) string {
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return "transport error"
}

func statusError(resp *http.Response, what string) error {
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: access to %s denied", ErrUnavailable, what)
	default:
		return fmt.Errorf("%w: %s answered %d", ErrUnavailable, what, resp.StatusCode)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
