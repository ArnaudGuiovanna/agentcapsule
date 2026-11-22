package addrpolicy

import (
	"net/netip"
	"regexp"
	"strings"
)

// InternalHost reports whether a provider URL's host names a non-public
// address without asking DNS: an IP address that is not public, localhost, or
// a numeric form that some resolvers read as an address (127.1, 2130706433).
// The API refuses such a URL at registration (internal/controlplane). The real
// guard is the check when the gateway connects, after DNS resolution. It moved
// here from internal/llmgateway, which the control plane does not import.
func InternalHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return Classify(a) != Public
	}
	name := HostName(host)
	return name == "localhost" || strings.HasSuffix(name, ".localhost") || NumericName(name)
}

// HostName is a host name as the policies compare it: in lower case, without
// its trailing dot.
func HostName(host string) string { return strings.TrimSuffix(strings.ToLower(host), ".") }

var numericLabel = regexp.MustCompile(`^(0x[0-9a-f]*|[0-9]+)$`)

// NumericName: a top-level label is never numeric, so such a name is an
// address in a form that inet_aton accepts.
func NumericName(name string) bool {
	return numericLabel.MatchString(name[strings.LastIndex(name, ".")+1:])
}
