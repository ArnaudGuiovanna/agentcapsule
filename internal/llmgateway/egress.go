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
)

// ErrAddressRefused: the provider's address is not public and the operator
// did not allow it, or it is never allowed. Nothing was sent. It is a refusal:
// retrying will not help until the provider's URL or the operator's
// configuration changes.
var ErrAddressRefused = fmt.Errorf("%w: provider address not allowed", ErrRejected)

// ErrAllowlist: an entry of the operator's allowlist is not a "host:port" or
// a CIDR prefix of internal addresses.
var ErrAllowlist = errors.New("invalid internal provider allowlist")

// Addresses never dialed, whatever the allowlist says, besides the
// unspecified, multicast and link-local ones (169.254.0.0/16 and fe80::/10,
// where most clouds serve instance metadata): "this network", and the
// metadata services that live in other ranges.
var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	metadata    = map[netip.Addr]bool{
		netip.MustParseAddr("100.100.100.200"): true, // Alibaba Cloud
		netip.MustParseAddr("168.63.129.16"):   true, // Azure host services
		netip.MustParseAddr("fd00:ec2::254"):   true, // AWS instance metadata
		netip.MustParseAddr("fd00:ec2::23"):    true, // AWS EKS pod identity
		netip.MustParseAddr("fd20:ce::254"):    true, // Google Cloud metadata
	}
	// nat64 embeds an IPv4 address that a NAT64 gateway connects to.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
)

// internalRanges are the addresses that are not public: refused unless the
// operator allows them. Loopback, private (RFC 1918, RFC 4193), shared
// address space (carrier-grade NAT, RFC 6598), and the other special-purpose
// ranges no public provider uses.
var internalRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/8"), // loopback, IPv4-compatible and other reserved forms
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
}

type addressClass int

const (
	public   addressClass = iota
	internal              // refused unless the operator allows it
	never                 // refused even when the allowlist covers it
)

// effective is the address a connection reaches: an IPv4-mapped IPv6 address
// and a NAT64 address (64:ff9b::/96) reach the IPv4 address they carry.
func effective(a netip.Addr) netip.Addr {
	a = a.WithZone("").Unmap()
	if nat64.Contains(a) {
		b := a.As16()
		return netip.AddrFrom4([4]byte(b[12:]))
	}
	return a
}

func classify(a netip.Addr) addressClass {
	a = effective(a)
	switch {
	case !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || thisNetwork.Contains(a) || metadata[a]:
		return never
	}
	for _, r := range internalRanges {
		if r.Contains(a) {
			return internal
		}
	}
	return public
}

// InternalHost reports whether a provider URL's host names a non-public
// address without asking DNS: an IP address that is not public, localhost, or
// a numeric form that some resolvers read as an address (127.1, 2130706433).
// The API refuses such a URL at registration. The real guard is the check
// when the gateway connects, after DNS resolution.
func InternalHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return classify(a) != public
	}
	name := normalName(host)
	return name == "localhost" || strings.HasSuffix(name, ".localhost") || numericName(name)
}

func normalName(host string) string { return strings.TrimSuffix(strings.ToLower(host), ".") }

var numericLabel = regexp.MustCompile(`^(0x[0-9a-f]*|[0-9]+)$`)

// numericName: a top-level label is never numeric, so such a name is an
// address in a form that inet_aton accepts.
func numericName(name string) bool {
	return numericLabel.MatchString(name[strings.LastIndex(name, ".")+1:])
}

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
			if err != nil || p != p.Masked() || !insideInternal(p) {
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
			if a.Zone() != "" || classify(a) != internal {
				return Allowlist{}, fmt.Errorf("%w: %q is not an internal address that may be allowed", ErrAllowlist, e)
			}
			l.addrs[netip.AddrPortFrom(effective(a), uint16(port))] = true
			continue
		}
		name := normalName(host)
		if len(name) > 253 || !namePattern.MatchString(name) || numericName(name) {
			return Allowlist{}, fmt.Errorf("%w: %q is not a host name", ErrAllowlist, e)
		}
		l.names[name+":"+strconv.Itoa(int(port))] = true
	}
	return l, nil
}

// insideInternal: the prefix lies within one internal range, so it opens no
// public or never-allowed address by mistake.
func insideInternal(p netip.Prefix) bool {
	if p.Addr().Zone() != "" || p.Addr().Is4In6() {
		return false
	}
	for _, r := range internalRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
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

// egress is the gateway's address policy. It applies when a connection is
// opened, after DNS resolution: a public name that resolves to an internal
// address is refused like the address itself.
type egress struct {
	allow    Allowlist
	loopback bool // tests only
	lookup   func(context.Context, string) ([]netip.Addr, error)
	dialer   net.Dialer
}

func (e *egress) allowed(name string, port uint16, a netip.Addr) bool {
	a = effective(a)
	switch classify(a) {
	case public:
		return true
	case never:
		return false
	}
	return e.loopback && a.IsLoopback() || e.allow.covers(name, port, a)
}

// dial connects only to the allowed addresses of the host, in the
// resolver's order.
func (e *egress) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	port, perr := strconv.ParseUint(portText, 10, 16)
	if err != nil || perr != nil {
		return nil, ErrAddressRefused
	}
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, a)
	} else if addrs, err = e.lookup(ctx, host); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no address", Name: host, IsNotFound: true}
	}
	name := normalName(host)
	var last error = ErrAddressRefused
	for _, a := range addrs {
		if !e.allowed(name, uint16(port), a) {
			continue
		}
		conn, err := e.dialer.DialContext(ctx, network, netip.AddrPortFrom(a, uint16(port)).String())
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
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
// not to the provider), and every connection passes the address policy.
func newClient(allow Allowlist, t TestOptions) *http.Client {
	e := &egress{allow: allow, loopback: t.Loopback, lookup: t.Lookup, dialer: net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}}
	if e.lookup == nil {
		e.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = e.dial
	if t.RootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: t.RootCAs, MinVersion: tls.VersionTLS12}
	}
	var rt http.RoundTripper = transport
	if t.Transport != nil {
		rt = t.Transport(transport)
	}
	return &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
