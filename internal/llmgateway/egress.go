package llmgateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/addrpolicy"
)

// ErrAddressRefused: the provider's address is not public and the operator
// did not allow it, or it is never allowed. Nothing was sent. It is a refusal:
// retrying will not help until the provider's URL or the operator's
// configuration changes.
var ErrAddressRefused = fmt.Errorf("%w: provider address not allowed", ErrRejected)

// ErrAllowlist: an entry of the operator's allowlist is not a "host:port" or
// a CIDR prefix of internal addresses.
var ErrAllowlist = errors.New("invalid internal provider allowlist")

// Allowlist is the operator's list of internal provider addresses the gateway
// may connect to (ADR 010, question 2). It is empty by default.
type Allowlist struct {
	names    map[string]bool // "name:port"
	addrs    map[netip.AddrPort]bool
	prefixes []netip.Prefix
}

var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ParseAllowlist reads the operator's entries. Each one is either:
//   - "host:port": a name, or an internal address, with its port. A name
//     allows the provider URLs with that host and port, whatever internal
//     address the name resolves to. An address allows that address and port,
//     whatever name the URL uses;
//   - a CIDR prefix inside one internal range, such as "10.0.0.0/24": every
//     address in it, on every port.
//
// Unspecified, multicast, link-local and cloud metadata addresses are never
// allowed: an entry that names one is refused, and a prefix that covers one
// does not open it.
func ParseAllowlist(entries []string) (Allowlist, error) {
	l := Allowlist{names: map[string]bool{}, addrs: map[netip.AddrPort]bool{}}
	for _, e := range entries {
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil || p != p.Masked() || !addrpolicy.InsideInternal(p) {
				return Allowlist{}, fmt.Errorf("%w: %q is not a prefix of internal addresses", ErrAllowlist, e)
			}
			l.prefixes = append(l.prefixes, p)
			continue
		}
		host, portText, err := net.SplitHostPort(e)
		port, perr := strconv.ParseUint(portText, 10, 16)
		if err != nil || perr != nil || port == 0 {
			return Allowlist{}, fmt.Errorf("%w: %q is not host:port", ErrAllowlist, e)
		}
		if a, err := netip.ParseAddr(host); err == nil {
			if a.Zone() != "" || addrpolicy.Classify(a) != addrpolicy.Internal {
				return Allowlist{}, fmt.Errorf("%w: %q is not an internal address that may be allowed", ErrAllowlist, e)
			}
			l.addrs[netip.AddrPortFrom(addrpolicy.Effective(a), uint16(port))] = true
			continue
		}
		name := addrpolicy.HostName(host)
		if len(name) > 253 || !namePattern.MatchString(name) || addrpolicy.NumericName(name) {
			return Allowlist{}, fmt.Errorf("%w: %q is not a host name", ErrAllowlist, e)
		}
		l.names[name+":"+strconv.Itoa(int(port))] = true
	}
	return l, nil
}

func (l Allowlist) covers(name string, port uint16, a netip.Addr) bool {
	if l.names[name+":"+strconv.Itoa(int(port))] || l.addrs[netip.AddrPortFrom(a, port)] {
		return true
	}
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Allows reports whether the list allows the internal address a, reached as
// host:port. The corpus source client (internal/corpussource) reads its
// operator's list, corpus.sources.allowed_internal_hosts, in this syntax.
func (l Allowlist) Allows(host string, port uint16, a netip.Addr) bool {
	return l.covers(addrpolicy.HostName(host), port, addrpolicy.Effective(a))
}

// egress is the gateway's address policy. It applies when a connection is
// opened, after DNS resolution (addrpolicy.Dialer): a public name that
// resolves to an internal address is refused like the address itself.
type egress struct {
	allow    Allowlist
	loopback bool // tests only
}

func (e *egress) allowed(host string, port uint16, a netip.Addr) bool {
	a = addrpolicy.Effective(a)
	switch addrpolicy.Classify(a) {
	case addrpolicy.Public:
		return true
	case addrpolicy.Never:
		return false
	}
	return e.loopback && a.IsLoopback() || e.allow.covers(addrpolicy.HostName(host), port, a)
}

// TestOptions change a gateway in ways the operator's configuration cannot.
// Only NewForTests takes them, and only in a test binary.
type TestOptions struct {
	// Loopback lets the gateway connect to loopback addresses, where tests
	// run their mock providers.
	Loopback bool
	// RootCAs replaces the system's CAs, for a test TLS server.
	RootCAs *x509.CertPool
	// Lookup replaces DNS resolution.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Transport wraps the gateway's transport, to count or cut requests. The
	// address policy stays underneath.
	Transport func(http.RoundTripper) http.RoundTripper
}

// NewForTests is New with test options. It panics outside a test binary
// built by go test, so that no production path can reach the options.
func NewForTests(c Config, t TestOptions) *Gateway {
	if !testing.Testing() {
		panic("llmgateway: NewForTests outside a test binary")
	}
	return newGateway(c, t)
}

// newClient is the gateway's only HTTP client: no redirect is followed, no
// environment proxy is used (the address check would then apply to the proxy,
// not to the provider), and every connection passes the address policy. It
// keeps idlePerHost idle connections to each provider address.
func newClient(allow Allowlist, idlePerHost int, t TestOptions) *http.Client {
	e := &egress{allow: allow, loopback: t.Loopback}
	dialer := &addrpolicy.Dialer{Allow: e.allowed, Refused: ErrAddressRefused, Lookup: t.Lookup,
		Connect: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	transport.MaxIdleConnsPerHost = idlePerHost
	transport.MaxIdleConns = max(transport.MaxIdleConns, idlePerHost)
	if t.RootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: t.RootCAs, MinVersion: tls.VersionTLS12}
	}
	var rt http.RoundTripper = transport
	if t.Transport != nil {
		rt = t.Transport(transport)
	}
	return &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
