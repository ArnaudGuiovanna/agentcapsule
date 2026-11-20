package addrpolicy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewTransport is the HTTP transport of an outbound client: every
// connection goes through the dialer's address policy, and environment
// proxies are ignored, since the check would then see the proxy rather than
// the destination. roots replaces the system's CAs, for a test server only.
// The harness registry client (internal/ociregistry) and the corpus source
// client (internal/corpussource) share it.
func NewTransport(d *Dialer, roots *x509.CertPool) *http.Transport {
	t := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if roots != nil {
		t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return t
}

// Redirects is the redirect policy of an outbound client: at most max
// redirects per request, each to a URL that allowed accepts and that carries
// no user information; refused wraps every refusal. The Authorization header
// leaves the request as soon as its host differs from the first request's,
// and does not come back on a later hop to that host: Go keeps it for a
// subdomain or another port of the same name, and copies it again from the
// first request at each hop.
func Redirects(max int, refused error, allowed func(*url.URL) bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > max {
			return fmt.Errorf("%w: too many redirects", refused)
		}
		if req.URL.User != nil || !allowed(req.URL) {
			return fmt.Errorf("%w: redirect to an unapproved host", refused)
		}
		home := via[0].URL.Host
		for _, r := range append(via[1:], req) {
			if !strings.EqualFold(r.URL.Host, home) {
				req.Header.Del("Authorization")
				break
			}
		}
		return nil
	}
}
