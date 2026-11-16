package ociregistry

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// fakeNetwork stands for DNS and the network. A name resolves to the
// addresses listed for it; a connection to "address:port" reaches the test
// server routed there, if any. Every connection attempt is recorded, so a
// test sees what the client would have dialed.
type fakeNetwork struct {
	mu     sync.Mutex
	names  map[string][]netip.Addr
	routes map[string]string // "address:port" -> test server address
	dialed []string
}

func newFakeNetwork() *fakeNetwork {
	return &fakeNetwork{names: map[string][]netip.Addr{}, routes: map[string]string{}}
}

func (f *fakeNetwork) resolve(name string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.names[name] = nil
	for _, a := range addrs {
		f.names[name] = append(f.names[name], netip.MustParseAddr(a))
	}
}

func (f *fakeNetwork) route(address string, srv *httptest.Server) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[address] = srv.Listener.Addr().String()
}

func (f *fakeNetwork) attempts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

func (f *fakeNetwork) on(roots *x509.CertPool) network {
	return network{rootCAs: roots,
		lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if a, ok := f.names[host]; ok {
				return a, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
		connect: func(ctx context.Context, network, address string) (net.Conn, error) {
			f.mu.Lock()
			f.dialed = append(f.dialed, address)
			to, ok := f.routes[address]
			f.mu.Unlock()
			if !ok {
				return nil, errors.New("fake network: no route")
			}
			var d net.Dialer
			return d.DialContext(ctx, network, to)
		},
	}
}

func trust(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// The classes come from internal/addrpolicy, shared with the model gateway.
// A rule allows public addresses; a local rule also internal ones; no rule
// allows the unspecified, multicast, link-local, "this network" and cloud
// metadata addresses. Before the shared classes, a public rule allowed
// 0.1.2.3, the NAT64 form of 10.0.0.1 and Azure's 168.63.129.16, and a local
// rule allowed everything.
func TestRuleAddressClasses(t *testing.T) {
	public := Rule{Host: "registry.example", Repositories: []string{"x/"}}
	local := Rule{Host: "registry.lan:5000", Repositories: []string{"x/"}, Local: true}
	for _, c := range []struct {
		addr          string
		public, local bool
	}{
		{"8.8.8.8", true, true},
		{"2606:4700::1111", true, true},
		{"64:ff9b::808:808", true, true}, // NAT64 of 8.8.8.8
		{"127.0.0.1", false, true},
		{"::1", false, true},
		{"10.0.0.5", false, true},
		{"192.168.1.9", false, true},
		{"100.64.0.1", false, true},
		{"fd12::1", false, true},
		{"::ffff:10.0.0.1", false, true},
		{"64:ff9b::a00:1", false, true}, // NAT64 of 10.0.0.1
		{"0.1.2.3", false, false},
		{"0.0.0.0", false, false},
		{"::", false, false},
		{"224.0.0.1", false, false},
		{"169.254.169.254", false, false},
		{"169.254.170.2", false, false},
		{"fe80::1", false, false},
		{"168.63.129.16", false, false},
		{"100.100.100.200", false, false},
		{"fd00:ec2::254", false, false},
		{"fd00:ec2::23", false, false},
		{"fd20:ce::254", false, false},
		{"::ffff:169.254.169.254", false, false},
		{"64:ff9b::a9fe:a9fe", false, false}, // NAT64 of 169.254.169.254
	} {
		a := netip.MustParseAddr(c.addr)
		if got := public.allowsAddress(a); got != c.public {
			t.Errorf("public rule, %s: %v, want %v", c.addr, got, c.public)
		}
		if got := local.allowsAddress(a); got != c.local {
			t.Errorf("local rule, %s: %v, want %v", c.addr, got, c.local)
		}
	}
}

// A public name that resolves to an internal address is refused like the
// address itself, through the real import path, and nothing is dialed. A
// name with several addresses dials only the public ones.
func TestPublicRuleChecksTheAddressANameResolvesTo(t *testing.T) {
	rule := Rule{Host: "registry.example", Repositories: []string{"acme/"}}
	ref, err := ParseReference("registry.example/acme/echo@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeNetwork()
	f, err := NewFetcher(Policy{Rules: []Rule{rule}}, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	f.clients[rule.Host] = newClientOn(rule, 0, fake.on(nil))
	for _, addr := range []string{"127.0.0.1", "10.0.0.1", "0.1.2.3", "64:ff9b::a00:1", "168.63.129.16", "169.254.169.254", "fd00:ec2::254"} {
		fake.resolve("registry.example", addr)
		if _, err := f.Fetch(t.Context(), ref, t.TempDir()); !errors.Is(err, ErrPolicy) {
			t.Errorf("registry.example at %s: %v, want a policy refusal", addr, err)
		}
	}
	if dialed := fake.attempts(); len(dialed) != 0 {
		t.Fatal("refused addresses dialed:", dialed)
	}
	// Literal addresses in a URL take the same check.
	c := newClientOn(rule, 0, fake.on(nil))
	for _, u := range []string{"https://0.1.2.3/v2/", "https://[64:ff9b::a00:1]/v2/", "https://168.63.129.16/v2/", "https://[::ffff:10.0.0.1]/v2/"} {
		if _, err := c.http.Get(u); !errors.Is(err, ErrPolicy) {
			t.Errorf("%s: %v, want a policy refusal", u, err)
		}
	}
	if dialed := fake.attempts(); len(dialed) != 0 {
		t.Fatal("refused addresses dialed:", dialed)
	}
	// A mixed answer: the internal address is skipped, the public one dialed
	// (and unreachable here, so the registry is unavailable, not refused).
	fake.resolve("registry.example", "10.0.0.1", "8.8.8.8")
	if _, err := f.Fetch(t.Context(), ref, t.TempDir()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("mixed answer:", err)
	}
	if dialed := fake.attempts(); len(dialed) != 1 || dialed[0] != "8.8.8.8:443" {
		t.Fatal("mixed answer dialed:", dialed)
	}
}

// A redirect to an approved blob host (a registry's CDN) is followed, and its
// connection takes the same address check: a blob host that resolves to an
// internal or metadata address is refused, without being dialed.
func TestRedirectToABlobHostIsCheckedWhenItConnects(t *testing.T) {
	// The test servers' certificate names example.com.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.URL.Query().Get("to")+"/blob", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	var auth sync.Map
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			auth.Store("seen", true)
		}
		_, _ = w.Write([]byte("blob"))
	}))
	defer cdn.Close()
	fake := newFakeNetwork()
	fake.resolve("example.com", "8.8.8.8")
	fake.route("8.8.8.8:443", origin)
	fake.route("8.8.8.8:8443", cdn)
	rule := Rule{Host: "example.com", Repositories: []string{"acme/"}, BlobHosts: []string{"example.com:8443", "cdn.example.net"}}
	if err := (Policy{Rules: []Rule{rule}}).Validate(); err != nil {
		t.Fatal(err)
	}
	c := newClientOn(rule, 0, fake.on(trust(origin)))
	get := func(to string) error {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/v2/acme/echo/blobs/x?to="+to, nil)
		req.Header.Set("Authorization", "Bearer registry-token")
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "blob" {
			t.Fatal("redirected download:", resp.StatusCode, string(body))
		}
		return nil
	}
	if err := get("example.com:8443"); err != nil {
		t.Fatal("a redirect to a public blob host was refused:", err)
	}
	if _, seen := auth.Load("seen"); seen {
		t.Fatal("the registry's token followed the redirect")
	}
	for _, addr := range []string{"10.0.0.1", "127.0.0.1", "0.1.2.3", "64:ff9b::a00:1", "168.63.129.16", "169.254.169.254"} {
		fake.resolve("cdn.example.net", addr)
		if err := get("cdn.example.net"); !errors.Is(err, ErrPolicy) {
			t.Errorf("a blob host at %s: %v, want a policy refusal", addr, err)
		}
	}
	for _, dialed := range fake.attempts() {
		if !strings.HasPrefix(dialed, "8.8.8.8:") {
			t.Fatal("a refused redirect target was dialed:", dialed)
		}
	}
}

// A local rule (development only) opens internal addresses, never the
// metadata and other always-refused ones: neither for the registry's own name
// nor for a redirect.
func TestLocalRuleNeverOpensMetadataAddresses(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://cdn.lan:5000/blob", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("blob")) }))
	defer cdn.Close()
	fake := newFakeNetwork()
	fake.route("10.0.0.5:5000", origin)
	fake.route("192.168.1.9:5000", cdn)
	rule := Rule{Host: "registry.lan:5000", Repositories: []string{"acme/"}, BlobHosts: []string{"cdn.lan:5000"}, Local: true}
	c := newClientOn(rule, 0, fake.on(nil))
	metadata := []string{"169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "fd00:ec2::23",
		"fd20:ce::254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "0.1.2.3", "0.0.0.0", "fe80::1"}
	for _, addr := range metadata {
		fake.resolve("registry.lan", addr)
		if _, err := c.http.Get("http://registry.lan:5000/v2/"); !errors.Is(err, ErrPolicy) {
			t.Errorf("registry.lan at %s: %v, want a policy refusal", addr, err)
		}
	}
	if dialed := fake.attempts(); len(dialed) != 0 {
		t.Fatal("always-refused addresses dialed:", dialed)
	}
	// The registry and its CDN on the operator's network are reachable.
	fake.resolve("registry.lan", "10.0.0.5")
	fake.resolve("cdn.lan", "192.168.1.9")
	resp, err := c.http.Get("http://registry.lan:5000/v2/acme/echo/blobs/x")
	if err != nil {
		t.Fatal("a local rule refused an internal address:", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "blob" {
		t.Fatal("redirected download:", string(body))
	}
	// A redirect to a CDN name that resolves to a metadata address is refused.
	// The connection already open to cdn.lan was checked when it opened;
	// close it so that the next request resolves the name again.
	c.http.CloseIdleConnections()
	for _, addr := range metadata {
		fake.resolve("cdn.lan", addr)
		if _, err := c.http.Get("http://registry.lan:5000/v2/acme/echo/blobs/x"); !errors.Is(err, ErrPolicy) {
			t.Errorf("a blob host at %s: %v, want a policy refusal", addr, err)
		}
	}
	for _, dialed := range fake.attempts() {
		if dialed != "10.0.0.5:5000" && dialed != "192.168.1.9:5000" {
			t.Fatal("an always-refused address was dialed:", dialed)
		}
	}
	// A rule written with a metadata address is refused when it connects.
	literal := newClientOn(Rule{Host: "169.254.169.254:80", Repositories: []string{"acme/"}, Local: true}, 0, fake.on(nil))
	if _, err := literal.http.Get(literal.base() + "/v2/"); !errors.Is(err, ErrPolicy) {
		t.Fatal("a local rule at a metadata address:", err)
	}
}
