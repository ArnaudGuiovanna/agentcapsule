package addrpolicy

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func redirectChain(t *testing.T, urls ...string) (*http.Request, []*http.Request) {
	t.Helper()
	var via []*http.Request
	for _, u := range urls[:len(urls)-1] {
		r, err := http.NewRequest("GET", u, nil)
		if err != nil {
			t.Fatal(err)
		}
		via = append(via, r)
	}
	next, err := http.NewRequest("GET", urls[len(urls)-1], nil)
	if err != nil {
		t.Fatal(err)
	}
	next.Header.Set("Authorization", "Bearer forge-token") // gitleaks:allow test fixture, not a credential
	return next, via
}

// A redirect is followed at most max times, only to a URL the caller
// allows, and Authorization leaves the request as soon as the host differs
// from the first request's, even for a subdomain that Go would keep it for,
// and does not come back on a later hop to the first host.
func TestRedirectsFollowOnlyAllowedHostsAndDropAuthorization(t *testing.T) {
	refused := errors.New("refused")
	allowed := func(u *url.URL) bool { return u.Scheme == "https" && strings.HasSuffix(u.Host, "forge.example") }
	check := Redirects(2, refused, allowed)

	next, via := redirectChain(t, "https://forge.example/a", "https://forge.example/b")
	if err := check(next, via); err != nil || next.Header.Get("Authorization") == "" {
		t.Fatal("a redirect to the same host lost its credential or was refused:", err)
	}
	next, via = redirectChain(t, "https://forge.example/a", "https://codeload.forge.example/b")
	if err := check(next, via); err != nil || next.Header.Get("Authorization") != "" {
		t.Fatal("the credential followed a redirect to another host (a subdomain):", err)
	}
	next, via = redirectChain(t, "https://forge.example/a", "https://codeload.forge.example/b", "https://forge.example/c")
	if err := check(next, via); err != nil || next.Header.Get("Authorization") != "" {
		t.Fatal("the credential came back after a hop through another host:", err)
	}
	next, via = redirectChain(t, "https://forge.example/a", "https://forge.example/b", "https://forge.example/c", "https://forge.example/d")
	if err := check(next, via); !errors.Is(err, refused) {
		t.Fatal("a third redirect was followed:", err)
	}
	for _, target := range []string{"https://elsewhere.example/b", "http://forge.example/b", "https://user@forge.example/b"} {
		next, via = redirectChain(t, "https://forge.example/a", target)
		if err := check(next, via); !errors.Is(err, refused) {
			t.Error("a redirect to", target, "was followed:", err)
		}
	}
}

// The transport ignores environment proxies, so the address check sees the
// destination, and dials through the policy's dialer.
func TestTransportDialsThroughThePolicy(t *testing.T) {
	d := &Dialer{Allow: func(string, uint16, netip.Addr) bool { return false }, Refused: errors.New("refused")}
	tr := NewTransport(d, nil)
	if tr.Proxy != nil || tr.DialContext == nil || tr.TLSClientConfig != nil {
		t.Fatal("the transport uses a proxy, no policy dialer, or a custom TLS configuration without roots")
	}
}
