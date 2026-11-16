package llmgateway

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// trust returns a pool that holds a test TLS server's certificate.
func trust(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// mockProvider answers every request as an OpenAI-compatible provider and
// counts them.
func mockProvider(t *testing.T, secure bool) (*httptest.Server, string, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	})
	srv := httptest.NewUnstartedServer(handler)
	if secure {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return srv, port, calls
}

func openAIRoute(base string) Route {
	return Route{Kind: "openai_compatible", BaseURL: base, UpstreamModel: "m", Secret: "sk-provider-key", Key: "t/p"}
}

const forwardBody = `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":5}`

func TestAddressClasses(t *testing.T) {
	for want, addrs := range map[addressClass][]string{
		public: {"8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"},
		internal: {"127.0.0.1", "127.8.9.10", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd12:3456::1",
			"100.64.0.1", "100.127.255.254", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a00:1", "198.18.0.1", "::127.0.0.1"},
		never: {"0.0.0.0", "::", "0.1.2.3", "224.0.0.1", "239.255.255.250", "ff02::1", "169.254.169.254", "169.254.170.2", "169.254.0.23",
			"fe80::1", "fe80::1%eth0", "168.63.129.16", "100.100.100.200", "fd00:ec2::254", "fd00:ec2::23", "fd20:ce::254",
			"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "::ffff:0.0.0.0"},
	} {
		for _, text := range addrs {
			if got := classify(netip.MustParseAddr(text)); got != want {
				t.Errorf("%s: class %d, want %d", text, got, want)
			}
		}
	}
}

func TestInternalHostSeesLiteralAddressesAndLocalhost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "10.0.0.7", "192.168.1.20", "169.254.169.254", "168.63.129.16", "fd00:ec2::254",
		"fe80::1%eth0", "::ffff:127.0.0.1", "0.0.0.0", "localhost", "LOCALHOST.", "models.localhost", "127.1", "2130706433", "0x7f000001", "0177.0.0.1"} {
		if !InternalHost(host) {
			t.Errorf("%s not seen as internal", host)
		}
	}
	for _, host := range []string{"api.openai.com", "API.Anthropic.com.", "llm.example.org", "1.1.1.1", "2606:4700::1111", "models.internal", "a1b2.example"} {
		if InternalHost(host) {
			t.Errorf("%s seen as internal", host)
		}
	}
}

func TestParseAllowlist(t *testing.T) {
	l, err := ParseAllowlist([]string{"Models.Example.NET.:11434", "localhost:8080", "10.0.0.7:443", "[::1]:11434", "[::ffff:192.168.1.9]:80",
		"10.0.0.0/24", "fd00::/8", "100.64.0.0/10", "127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	for _, c := range []struct {
		name string
		port uint16
		addr string
		want bool
	}{
		{"models.example.net", 11434, "192.168.5.5", true},
		{"models.example.net", 443, "192.168.5.5", false},
		{"other.example.net", 11434, "192.168.5.5", false},
		{"localhost", 8080, "127.0.0.1", true},
		{"anything", 443, "10.0.0.7", true},
		{"anything", 444, "10.0.0.7", true}, // inside 10.0.0.0/24
		{"anything", 444, "10.0.1.7", false},
		{"anything", 11434, "::1", true},
		{"anything", 80, "192.168.1.9", true},
		{"anything", 1, "fd12::1", true},
		{"anything", 1, "100.80.0.1", true},
		{"anything", 1, "127.0.0.2", false},
	} {
		if got := l.covers(c.name, c.port, a(c.addr)); got != c.want {
			t.Errorf("%s:%d at %s: %v, want %v", c.name, c.port, c.addr, got, c.want)
		}
	}
	if empty, err := ParseAllowlist(nil); err != nil || empty.covers("localhost", 11434, a("127.0.0.1")) || empty.covers("x", 1, a("10.0.0.1")) {
		t.Fatal("no entry must allow nothing", err)
	}
	for _, bad := range []string{
		"", "models.example.net", "models.example.net:0", "models.example.net:65536", "models.example.net:http", "bad_name.example:80",
		"127.1:80", "2130706433:80", "0x7f.1:80", // names that resolvers read as addresses
		"8.8.8.8:443", "169.254.169.254:80", "[fe80::1%eth0]:80", "168.63.129.16:80", "0.0.0.0:80", "[::]:80", "224.0.0.1:80",
		"0.0.0.0/0", "::/0", "8.8.8.0/24", "10.0.0.1/24", "169.254.0.0/16", "fe80::/10", "100.0.0.0/8", "::ffff:10.0.0.0/104", "10.0.0.0/33",
	} {
		if _, err := ParseAllowlist([]string{bad}); !errors.Is(err, ErrAllowlist) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

// With the production policy (no test option, no allowlist), every internal
// address is refused when the gateway connects: nothing reaches the mock
// provider, and the refusal is typed. Before the policy, the loopback forms
// reached it and carried the provider's key.
func TestGatewayRefusesInternalAddressesBeforeSending(t *testing.T) {
	srv, port, calls := mockProvider(t, false)
	g := fastWith(Config{Timeout: 2 * time.Second, MaxAttempts: 1, FailureLimit: 1}, TestOptions{})
	for _, base := range []string{srv.URL, "http://localhost:" + port, "http://[::ffff:127.0.0.1]:" + port, "http://[::1]:" + port,
		"http://0.0.0.0:" + port, "http://[64:ff9b::7f00:1]:" + port, "http://10.0.0.1:" + port, "http://192.168.1.1",
		"http://100.64.0.1", "http://169.254.169.254", "http://100.100.100.200", "http://[fd00:ec2::254]", "https://168.63.129.16"} {
		if _, err := g.Complete(t.Context(), openAIRoute(base), ask); !errors.Is(err, ErrAddressRefused) || !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v, want the address refusal", base, err)
		}
	}
	if _, err := g.Forward(t.Context(), openAIRoute(srv.URL), DialectOpenAI, []byte(forwardBody)); !errors.Is(err, ErrAddressRefused) {
		t.Error("forward:", err)
	}
	if calls.Load() != 0 {
		t.Fatal("a request reached an internal address:", calls.Load())
	}
	// A refusal is the configuration's fault, not the provider's: with a
	// failure limit of 1, the breaker stays closed for an allowed provider.
	allowed, err := ParseAllowlist([]string{"127.0.0.1:" + port})
	if err != nil {
		t.Fatal(err)
	}
	g = fastWith(Config{MaxAttempts: 1, FailureLimit: 1, AllowInternal: allowed}, TestOptions{})
	if _, err = g.Complete(t.Context(), openAIRoute("http://[::1]:"+port), ask); !errors.Is(err, ErrAddressRefused) {
		t.Fatal("an address outside the allowlist:", err)
	}
	if out, err := g.Complete(t.Context(), openAIRoute(srv.URL), ask); err != nil || out.Text != "hello" {
		t.Fatal("the allowed address was refused:", err)
	}
}

// A public name that resolves to an internal address is refused like the
// address: the check applies when connecting, after DNS. The operator's
// allowlist opens it by name, by address or by prefix; nothing else does.
func TestGatewayChecksTheAddressANameResolvesTo(t *testing.T) {
	// The test server's certificate names example.com.
	srv, port, calls := mockProvider(t, true)
	var example atomic.Pointer[[]netip.Addr]
	example.Store(&[]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	answers := map[string][]netip.Addr{
		"metadata.example":    {netip.MustParseAddr("fd00:ec2::254")},
		"alibaba.example.com": {netip.MustParseAddr("100.100.100.200")},
	}
	var asked atomic.Int32
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		asked.Add(1)
		if host == "example.com" {
			return *example.Load(), nil
		}
		if a, ok := answers[host]; ok {
			return a, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	call := func(entries []string, base string) error {
		t.Helper()
		allow, err := ParseAllowlist(entries)
		if err != nil {
			t.Fatal(entries, err)
		}
		g := fastWith(Config{MaxAttempts: 1, AllowInternal: allow, RequireHTTPS: true}, TestOptions{RootCAs: trust(srv), Lookup: lookup})
		_, err = g.Complete(t.Context(), openAIRoute(base), ask)
		return err
	}
	name := "https://example.com:" + port
	if err := call(nil, name); !errors.Is(err, ErrAddressRefused) || calls.Load() != 0 || asked.Load() == 0 {
		t.Fatal("a public name resolving to loopback was not refused:", err, calls.Load(), asked.Load())
	}
	for _, entries := range [][]string{{"example.com:" + port}, {"EXAMPLE.com.:" + port}, {"127.0.0.1:" + port}, {"127.0.0.0/8"}} {
		before := calls.Load()
		if err := call(entries, name); err != nil || calls.Load() != before+1 {
			t.Fatal("allowed by", entries, "but refused:", err)
		}
	}
	for _, entries := range [][]string{{"example.com:1"}, {"other.example.com:" + port}, {"127.0.0.2:" + port}, {"10.0.0.0/8"}} {
		before := calls.Load()
		if err := call(entries, name); !errors.Is(err, ErrAddressRefused) || calls.Load() != before {
			t.Fatal("not allowed by", entries, "but called:", err)
		}
	}
	// A name with several addresses: the refused ones are skipped, the
	// allowed ones dialed.
	example.Store(&[]netip.Addr{netip.MustParseAddr("10.9.9.9"), netip.MustParseAddr("127.0.0.1")})
	before := calls.Load()
	if err := call([]string{"127.0.0.1:" + port}, name); err != nil || calls.Load() != before+1 {
		t.Fatal("the allowed address of a mixed answer was not dialed:", err)
	}
	if err := call(nil, name); !errors.Is(err, ErrAddressRefused) || calls.Load() != before+1 {
		t.Fatal("a mixed answer without an allowed address was dialed:", err)
	}
	// Metadata addresses stay refused even inside an allowed prefix.
	if err := call([]string{"fd00::/8"}, "https://metadata.example:"+port); !errors.Is(err, ErrAddressRefused) {
		t.Fatal("a metadata address was dialed:", err)
	}
	if err := call([]string{"100.64.0.0/10"}, "https://alibaba.example.com:"+port); !errors.Is(err, ErrAddressRefused) {
		t.Fatal("a metadata address was dialed:", err)
	}
	// A name that does not resolve is unavailable, not refused: it may come back.
	if err := call(nil, "https://unknown.example:"+port); !errors.Is(err, ErrUnavailable) {
		t.Fatal("an unresolved name:", err)
	}
}

// A redirect is never followed, even to an address the gateway may reach: the
// provider's key would go elsewhere. It is a refusal, not an unknown outcome,
// and it is not retried.
func TestGatewayNeverFollowsARedirect(t *testing.T) {
	target, _, reached := mockProvider(t, false)
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		var redirects atomic.Int32
		redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirects.Add(1)
			http.Redirect(w, r, target.URL+r.URL.Path, status)
		}))
		g := fast(Config{MaxAttempts: 3})
		if _, err := g.Complete(t.Context(), openAIRoute(redirect.URL), ask); !errors.Is(err, ErrRejected) || errors.Is(err, ErrAddressRefused) {
			t.Error(status, "complete:", err)
		}
		if _, err := g.Forward(t.Context(), openAIRoute(redirect.URL), DialectOpenAI, []byte(forwardBody)); !errors.Is(err, ErrRejected) {
			t.Error(status, "forward:", err)
		}
		redirect.Close()
		if redirects.Load() != 2 {
			t.Error(status, "a redirect was retried:", redirects.Load())
		}
	}
	if reached.Load() != 0 {
		t.Fatal("a redirect was followed:", reached.Load())
	}
}

// The gateway's client is its own: no environment proxy (the address check
// would then see the proxy, not the provider) and no redirect.
func TestGatewayClientIgnoresProxiesAndRedirects(t *testing.T) {
	g := New(Config{})
	transport, ok := g.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.DialContext == nil || g.http.CheckRedirect == nil {
		t.Fatal("the gateway's client may use a proxy, follow a redirect or skip the address check")
	}
}
