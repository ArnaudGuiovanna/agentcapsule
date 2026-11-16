package ociregistry

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/addrpolicy"
)

const (
	ociManifestType = "application/vnd.oci.image.manifest.v1+json"
	maxManifest     = 64 << 10
	maxToken        = 64 << 10
)

// errAddress: the rule's address policy refuses every address of the host.
// Nothing was sent.
var errAddress = fmt.Errorf("%w: address not allowed for this registry", ErrPolicy)

// client talks to one approved registry. It has its own transport so the
// address policy of that rule applies to every connection, including blob
// redirects and token requests. Environment proxies are ignored: the check
// would then see the proxy, not the registry.
type client struct {
	rule Rule
	http *http.Client
	mu   sync.Mutex
	auth map[string]string // repository -> Authorization header won from a challenge
}

// network replaces, in tests only, DNS resolution, the connection to an
// address the rule allows, and the trusted CAs. The rule's address policy
// stays the production one.
type network struct {
	lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
	connect func(ctx context.Context, network, address string) (net.Conn, error)
	rootCAs *x509.CertPool
}

func newClient(rule Rule, timeout time.Duration) *client {
	return newClientOn(rule, timeout, network{})
}

func newClientOn(rule Rule, timeout time.Duration, n network) *client {
	dialer := &addrpolicy.Dialer{
		Allow:   func(_ string, _ uint16, a netip.Addr) bool { return rule.allowsAddress(a) },
		Refused: errAddress,
		Lookup:  n.lookup,
		Connect: n.connect,
	}
	if dialer.Connect == nil {
		dialer.Connect = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if n.rootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: n.rootCAs, MinVersion: tls.VersionTLS12}
	}
	c := &client{rule: rule, auth: map[string]string{}}
	c.http = &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("%w: too many redirects", ErrPolicy)
		}
		if !c.allowedURL(req.URL, c.rule.BlobHosts) {
			return fmt.Errorf("%w: redirect to an unapproved host", ErrPolicy)
		}
		// Registry credentials and tokens stay with the registry. Go keeps the
		// header for a same-name host on another port or a subdomain; a CDN
		// authenticates the redirect URL itself.
		if !strings.EqualFold(req.URL.Host, c.rule.Host) {
			req.Header.Del("Authorization")
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

// do sends a registry request, anonymously at first. A 401 challenge is
// answered once: Bearer by fetching a token from the approved realm (with the
// rule's credentials, if any), Basic by sending the credentials to the
// registry itself. The winning header is reused for the repository.
func (c *client) do(ctx context.Context, repo, scope string, build func() (*http.Request, error)) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := build()
		if err != nil {
			return nil, err
		}
		req = req.WithContext(ctx)
		c.mu.Lock()
		auth := c.auth[repo]
		c.mu.Unlock()
		if auth != "" {
			req.Header.Set("Authorization", auth)
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
		scheme, params, _ := strings.Cut(strings.TrimSpace(challenge), " ")
		switch strings.ToLower(scheme) {
		case "bearer":
			token, err := c.fetchToken(ctx, scope, params)
			if err != nil {
				return nil, err
			}
			auth = "Bearer " + token
		case "basic":
			if c.rule.Username == "" {
				return nil, fmt.Errorf("%w: the registry requires credentials", ErrDenied)
			}
			auth = basicAuth(c.rule.Username, c.rule.Password)
		default:
			return nil, fmt.Errorf("%w: unsupported authentication challenge", ErrDenied)
		}
		c.mu.Lock()
		c.auth[repo] = auth
		c.mu.Unlock()
	}
	return nil, fmt.Errorf("%w: authentication loop", ErrUnavailable)
}

func basicAuth(user, password string) string {
	r := http.Request{Header: http.Header{}}
	r.SetBasicAuth(user, password)
	return r.Header.Get("Authorization")
}

// fetchToken asks the challenge's realm, which must be the registry or one of
// its approved token hosts, for a token covering scope.
func (c *client) fetchToken(ctx context.Context, scope, challenge string) (string, error) {
	params := parseChallenge(challenge)
	realm, err := url.Parse(params["realm"])
	if err != nil || !c.allowedURL(realm, c.rule.TokenHosts) {
		return "", fmt.Errorf("%w: token realm not approved", ErrPolicy)
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", ErrPolicy
	}
	if c.rule.Username != "" {
		req.SetBasicAuth(c.rule.Username, c.rule.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrPolicy) {
			return "", err
		}
		return "", fmt.Errorf("%w: token request failed", ErrUnavailable)
	}
	defer drain(resp)
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return "", fmt.Errorf("%w: the token service refused the credentials", ErrDenied)
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("%w: token request answered %d", ErrUnavailable, resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxToken)).Decode(&body); err != nil {
		return "", fmt.Errorf("%w: token response", ErrUnavailable)
	}
	token := body.Token
	if token == "" {
		token = body.AccessToken
	}
	if token == "" || !validCredential(token, maxToken) {
		return "", fmt.Errorf("%w: unusable token", ErrUnavailable)
	}
	return token, nil
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
		return fmt.Errorf("%w: access to %s refused", ErrDenied, what)
	default:
		return fmt.Errorf("%w: %s answered %d", ErrUnavailable, what, resp.StatusCode)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
