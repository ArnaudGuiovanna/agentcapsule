// Package addrpolicy classifies the addresses the worker's outbound clients
// connect to, and dials only the addresses a policy allows, after DNS
// resolution. The model gateway (internal/llmgateway) and the registry client
// (internal/ociregistry) share it, so their classes cannot drift
// (docs/adr/010-transport-security-and-preflight.md §4).
package addrpolicy

import (
	"context"
	"net"
	"net/netip"
	"strconv"
)

// Class is what a policy may do with an address.
type Class int

const (
	// Public addresses are always allowed.
	Public Class = iota
	// Internal addresses are refused unless the policy allows them.
	Internal
	// Never addresses are refused whatever the policy says.
	Never
)

// Addresses never dialed, besides the unspecified, multicast and link-local
// ones (169.254.0.0/16 and fe80::/10, where most clouds serve instance
// metadata): "this network", and the metadata services that live in other
// ranges.
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

// internalRanges are the addresses that are not public: loopback, private
// (RFC 1918, RFC 4193), shared address space (carrier-grade NAT, RFC 6598),
// and the other special-purpose ranges no public service uses.
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

// Effective is the address a connection reaches: an IPv4-mapped IPv6 address
// and a NAT64 address (64:ff9b::/96) reach the IPv4 address they carry.
func Effective(a netip.Addr) netip.Addr {
	a = a.WithZone("").Unmap()
	if nat64.Contains(a) {
		b := a.As16()
		return netip.AddrFrom4([4]byte(b[12:]))
	}
	return a
}

// Classify returns the class of the address a connection to a reaches.
func Classify(a netip.Addr) Class {
	a = Effective(a)
	switch {
	case !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || thisNetwork.Contains(a) || metadata[a]:
		return Never
	}
	for _, r := range internalRanges {
		if r.Contains(a) {
			return Internal
		}
	}
	return Public
}

// InsideInternal reports whether the prefix lies within one internal range,
// so that allowing it opens no public or Never address by mistake.
func InsideInternal(p netip.Prefix) bool {
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

// Dialer connects only to the addresses its policy allows. It checks each
// address after DNS resolution, so a public name that resolves to an internal
// address is refused like the address itself.
type Dialer struct {
	// Allow decides for one resolved address. host is the host of the dialed
	// address, as the caller wrote it.
	Allow func(host string, port uint16, a netip.Addr) bool
	// Refused is the error when no address of the host is allowed.
	Refused error
	// Lookup resolves a host name. Nil means the system resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Connect opens a connection to one allowed address, written
	// "address:port". Nil means a net.Dialer without options.
	Connect func(ctx context.Context, network, address string) (net.Conn, error)
}

// DialContext connects to the allowed addresses of the host, in the
// resolver's order, and returns the first connection. It fits
// http.Transport.DialContext.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	port, perr := strconv.ParseUint(portText, 10, 16)
	if err != nil || perr != nil {
		return nil, d.Refused
	}
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, a)
	} else if addrs, err = d.lookup(ctx, host); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no address", Name: host, IsNotFound: true}
	}
	connect := d.Connect
	if connect == nil {
		connect = (&net.Dialer{}).DialContext
	}
	last := d.Refused
	for _, a := range addrs {
		if !d.Allow(host, uint16(port), a) {
			continue
		}
		conn, err := connect(ctx, network, netip.AddrPortFrom(a, uint16(port)).String())
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

func (d *Dialer) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if d.Lookup != nil {
		return d.Lookup(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
