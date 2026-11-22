package addrpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// The table moved here from internal/llmgateway with the classification.
func TestAddressClasses(t *testing.T) {
	for want, addrs := range map[Class][]string{
		Public: {"8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"},
		Internal: {"127.0.0.1", "127.8.9.10", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd12:3456::1",
			"100.64.0.1", "100.127.255.254", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a00:1", "198.18.0.1", "::127.0.0.1"},
		Never: {"0.0.0.0", "::", "0.1.2.3", "224.0.0.1", "239.255.255.250", "ff02::1", "169.254.169.254", "169.254.170.2", "169.254.0.23",
			"fe80::1", "fe80::1%eth0", "168.63.129.16", "100.100.100.200", "fd00:ec2::254", "fd00:ec2::23", "fd20:ce::254",
			"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "::ffff:0.0.0.0"},
	} {
		for _, text := range addrs {
			if got := Classify(netip.MustParseAddr(text)); got != want {
				t.Errorf("%s: class %d, want %d", text, got, want)
			}
		}
	}
}

// IPv6 forms that reach or carry an IPv4 address take the class of that
// address: a 6to4 address (2002::/16) and both IPv4 addresses of a Teredo
// address (2001::/32: the server's, and the client's, stored inverted). The
// deprecated site-local range fec0::/10 is internal, as unique local
// addresses are.
func TestIPv6FormsWithAnEmbeddedIPv4TakeItsClass(t *testing.T) {
	for want, addrs := range map[Class][]string{
		// 6to4 of 8.8.8.8; Teredo with server 65.54.227.120 and client 8.8.8.8.
		Public: {"2002:808:808::1", "2002:808:808:1:2:3:4:5", "2001:0:4136:e378:8000:63bf:f7f7:f7f7"},
		Internal: {"fec0::1", "fec0:1:2:3::4", "feff:ffff::1",
			"2002:a00:1::1", "2002:7f00:1::", "2002:c0a8:101::1", "2002:6440:1::1", // 10.0.0.1, 127.0.0.1, 192.168.1.1, 100.64.0.1
			"2001:0:4136:e378:8000:63bf:f5ff:fffe", // client 10.0.0.1
			"2001:0:a00:1:8000:63bf:f7f7:f7f7",     // server 10.0.0.1
			"2001:0:4136:e378:8000:63bf:80ff:fffe", // client 127.0.0.1
		},
		Never: {"2002:a9fe:a9fe::1", "2002::1", "2002:e000:1::1", // 169.254.169.254, 0.0.0.0, 224.0.0.1
			"2001:0:4136:e378:8000:63bf:5601:5601", // client 169.254.169.254
			"2001:0:a9fe:a9fe::f7f7:f7f7",          // server 169.254.169.254
		},
	} {
		for _, text := range addrs {
			if got := Classify(netip.MustParseAddr(text)); got != want {
				t.Errorf("%s: class %d, want %d", text, got, want)
			}
		}
	}
	// A prefix over such forms is never inside an internal range: an operator
	// allows one only by its exact address.
	for _, p := range []string{"2002::/16", "2002:a00::/24", "2001::/32"} {
		if InsideInternal(netip.MustParsePrefix(p)) {
			t.Error(p, "seen inside an internal range")
		}
	}
	if !InsideInternal(netip.MustParsePrefix("fec0::/10")) {
		t.Error("fec0::/10 not seen inside an internal range")
	}
}

var errRefused = errors.New("refused")

// The dialer resolves the name, skips the refused addresses and connects to
// the allowed ones in the resolver's order. Without an allowed address it
// connects to nothing and returns its refusal; a name without an address is
// a DNS error, not a refusal.
func TestDialerConnectsOnlyToAllowedAddresses(t *testing.T) {
	answers := map[string][]netip.Addr{
		"mixed.example":   {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")},
		"private.example": {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("169.254.169.254")},
		"empty.example":   {},
	}
	var dialed []string
	d := &Dialer{
		Allow:   func(_ string, _ uint16, a netip.Addr) bool { return Classify(a) == Public },
		Refused: errRefused,
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			return answers[host], nil
		},
		Connect: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			if address == "8.8.8.8:443" {
				return nil, errors.New("connection refused")
			}
			client, server := net.Pipe()
			server.Close()
			return client, nil
		},
	}
	conn, err := d.DialContext(t.Context(), "tcp", "mixed.example:443")
	if err != nil || len(dialed) != 2 || dialed[0] != "8.8.8.8:443" || dialed[1] != "1.1.1.1:443" {
		t.Fatal("mixed answer:", err, dialed)
	}
	conn.Close()
	dialed = nil
	for _, address := range []string{"private.example:443", "[::ffff:127.0.0.1]:80", "0.1.2.3:80", "[64:ff9b::a00:1]:443", "168.63.129.16:80", "no-port", "x:99999"} {
		if _, err := d.DialContext(t.Context(), "tcp", address); !errors.Is(err, errRefused) {
			t.Error(address, err)
		}
	}
	var dnsErr *net.DNSError
	if _, err := d.DialContext(t.Context(), "tcp", "empty.example:443"); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Error("a name without an address:", err)
	}
	if len(dialed) != 0 {
		t.Fatal("refused addresses dialed:", dialed)
	}
}

func TestInsideInternal(t *testing.T) {
	for _, p := range []string{"10.0.0.0/24", "fd00::/8", "100.64.0.0/10", "127.0.0.1/32"} {
		if !InsideInternal(netip.MustParsePrefix(p)) {
			t.Error(p, "not seen inside an internal range")
		}
	}
	for _, p := range []string{"0.0.0.0/0", "::/0", "8.8.8.0/24", "169.254.0.0/16", "fe80::/10", "100.0.0.0/8", "::ffff:10.0.0.0/104"} {
		if InsideInternal(netip.MustParsePrefix(p)) {
			t.Error(p, "seen inside an internal range")
		}
	}
}
