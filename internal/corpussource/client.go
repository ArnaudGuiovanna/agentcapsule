package corpussource

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/addrpolicy"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// maxRedirects is the redirects one request may follow (ADR 023 C6).
const maxRedirects = 2

// errAddress: the rule's address policy refuses every address of the host.
// Nothing was sent.
var errAddress = fmt.Errorf("%w: address not allowed for this forge", ErrPolicy)

// TestNetwork replaces, in tests only, DNS resolution, the connection to an
// address the policy allows, and the trusted CAs. The address policy stays
// the production one. Only NewForTests takes it.
type TestNetwork struct {
	Lookup  func(ctx context.Context, host string) ([]netip.Addr, error)
	Connect func(ctx context.Context, network, address string) (net.Conn, error)
	RootCAs *x509.CertPool
}

// client talks to one approved forge. It has its own transport, so the
// rule's address policy applies to every connection, redirects included.
type client struct {
	rule Rule
	http *http.Client
}

func newClient(rule Rule, allow llmgateway.Allowlist, n TestNetwork) *client {
	dialer := &addrpolicy.Dialer{
		Allow: func(host string, port uint16, a netip.Addr) bool {
			switch addrpolicy.Classify(a) {
			case addrpolicy.Public:
				return true
			case addrpolicy.Internal:
				return rule.Local || allow.Allows(host, port, a)
			}
			return false
		},
		Refused: errAddress,
		Lookup:  n.Lookup,
		Connect: n.Connect,
	}
	if dialer.Connect == nil {
		dialer.Connect = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	transport := addrpolicy.NewTransport(dialer, n.RootCAs)
	// The host never decodes what it downloads, not even a gzip transfer
	// encoding: the bytes stored are the bytes the forge sent.
	transport.DisableCompression = true
	c := &client{rule: rule}
	c.http = &http.Client{Transport: transport, CheckRedirect: addrpolicy.Redirects(maxRedirects, ErrPolicy, c.allowedURL)}
	return c
}

// hosts are the hosts the rule lets the client reach: the forge, its API,
// and its archive and LFS hosts.
func (c *client) hosts() []string {
	return append(append([]string{c.rule.Host, c.rule.apiHost()}, c.rule.ArchiveHosts...), c.rule.LFSHosts...)
}

// allowedURL: HTTPS (plain HTTP only for a local rule), no user, to one of
// the rule's hosts.
func (c *client) allowedURL(u *url.URL) bool {
	if u.User != nil || !(u.Scheme == "https" || c.rule.Local && u.Scheme == "http") {
		return false
	}
	host := strings.ToLower(u.Host)
	for _, h := range c.hosts() {
		if host == h {
			return true
		}
	}
	return false
}

// forge reports whether host is the forge itself or its API: the only hosts
// a credential is sent to.
func (c *client) forge(host string) bool {
	host = strings.ToLower(host)
	return host == c.rule.Host || host == c.rule.apiHost()
}

func (c *client) scheme() string {
	if c.rule.Local {
		return "http://"
	}
	return "https://"
}

// api is the base URL of the forge's API.
func (c *client) api() string {
	base := c.scheme() + c.rule.apiHost()
	switch {
	case c.rule.Kind == GitLab:
		return base + "/api/v4"
	case c.rule.apiHost() == c.rule.Host:
		// GitHub Enterprise Server serves its API under its own host.
		return base + "/api/v3"
	}
	return base
}

// do sends one request. auth, when set, is the Authorization header, sent
// only to the forge itself; header holds headers a forge gave for this URL
// (an LFS download action). Every request names no compression.
func (c *client) do(ctx context.Context, method, raw string, body io.Reader, auth string, header map[string]string) (*http.Response, error) {
	u, err := url.Parse(raw)
	if err != nil || !c.allowedURL(u) {
		return nil, fmt.Errorf("%w: a URL outside the rule", ErrPolicy)
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, body)
	if err != nil {
		return nil, fmt.Errorf("%w: request", ErrPolicy)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	if auth != "" && c.forge(u.Host) {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("User-Agent", "agentcapsule-worker")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrPolicy) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %s", ErrUnavailable, "the attempt's time ran out")
		}
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, redact(err))
	}
	return resp, nil
}

// bearer is the API's Authorization header for a token; none without one.
func bearer(t Token) string {
	if t == "" {
		return ""
	}
	return "Bearer " + string(t)
}

// basic is the Git HTTP endpoints' Authorization header (the LFS batch API):
// the token as the password, with the user name each forge documents for a
// token.
func (c *client) basic(t Token) string {
	if t == "" {
		return ""
	}
	user := "x-access-token"
	if c.rule.Kind == GitLab {
		user = "oauth2"
	}
	r := http.Request{Header: http.Header{}}
	r.SetBasicAuth(user, string(t))
	return r.Header.Get("Authorization")
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// redact keeps a transport error useful without echoing a URL, which may
// carry a signed token.
func redact(err error) string {
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return "transport error"
}

// statusError maps a forge's answer to an error class. GitHub answers 404
// for a private repository a caller cannot see, and 422 for a ref that names
// no commit; a 403 or 429 with a rate limit is an outage, not a refusal.
func statusError(resp *http.Response, what string) error {
	code := resp.StatusCode
	limited := resp.Header.Get("Retry-After") != "" || resp.Header.Get("X-RateLimit-Remaining") == "0"
	switch {
	case code == http.StatusNotFound || code == http.StatusGone || code == http.StatusUnprocessableEntity || code == http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	case (code == http.StatusUnauthorized || code == http.StatusForbidden) && !limited:
		return fmt.Errorf("%w: access to %s refused", ErrDenied, what)
	}
	return fmt.Errorf("%w: %s answered %s", ErrUnavailable, what, strconv.Itoa(code))
}

// encoded reports a response whose bytes are not the content itself: the
// host would have to decode them, which it never does.
func encoded(resp *http.Response) bool {
	e := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding")))
	return e != "" && e != "identity"
}
