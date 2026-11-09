// Package ociregistry fetches and publishes harness packages over the OCI
// distribution API. It talks only to registries an operator approved, follows
// redirects only to approved hosts, never connects to private addresses unless
// a registry is explicitly marked local, and verifies every byte by digest.
package ociregistry

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	// ErrPolicy: the reference, registry, repository or a redirect target is
	// not allowed. Nothing was fetched from it.
	ErrPolicy = errors.New("registry reference not allowed")
	// ErrUnavailable: the registry could not be reached or answered an error;
	// retrying later may succeed.
	ErrUnavailable = errors.New("registry unavailable")
	// ErrNotFound: the registry answered that the manifest or a blob does not exist.
	ErrNotFound = errors.New("registry content not found")
	// ErrIntegrity: the registry served content that does not match its digest,
	// size or declared media type.
	ErrIntegrity = errors.New("registry content failed verification")
)

// Rule approves one registry and the repositories that may be used on it.
type Rule struct {
	// Host is the registry host and optional port, e.g. "ghcr.io".
	Host string `json:"host"`
	// Repositories are allowed repository prefixes: "org/" allows every
	// repository under org, "org/name" allows exactly that one.
	Repositories []string `json:"repositories"`
	// TokenHosts may serve bearer tokens for this registry, in addition to Host.
	TokenHosts []string `json:"token_hosts,omitempty"`
	// BlobHosts may serve redirected blob downloads (a registry's CDN), in
	// addition to Host. For GHCR: pkg-containers.githubusercontent.com.
	BlobHosts []string `json:"blob_hosts,omitempty"`
	// Local allows plain HTTP and private or loopback addresses. Only for a
	// registry on the operator's own network; never for a public one.
	Local bool `json:"local,omitempty"`
	// Username and Password authenticate pulls from a private registry. They
	// come from operator configuration and are never logged or returned.
	Username string `json:"-"`
	Password string `json:"-"`
}

// Policy is the installation's registry trust policy.
type Policy struct {
	Rules []Rule
}

var (
	hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$`)
	repoPart    = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
	tagPattern  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

func validHost(h string) bool { return len(h) <= 255 && hostPattern.MatchString(h) }

func validRepository(r string) bool {
	if r == "" || len(r) > 255 {
		return false
	}
	for _, p := range strings.Split(r, "/") {
		if !repoPart.MatchString(p) {
			return false
		}
	}
	return true
}

// Validate refuses rules that would widen the policy by accident.
func (p Policy) Validate() error {
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !validHost(r.Host) || seen[r.Host] || len(r.Repositories) == 0 {
			return fmt.Errorf("%w: rule for %q", ErrPolicy, r.Host)
		}
		seen[r.Host] = true
		if !r.Local && isIPLiteral(r.Host) {
			return fmt.Errorf("%w: a public rule must name a host, not an address", ErrPolicy)
		}
		for _, prefix := range r.Repositories {
			if !validRepository(strings.TrimSuffix(prefix, "/")) {
				return fmt.Errorf("%w: repository %q", ErrPolicy, prefix)
			}
		}
		for _, h := range append(append([]string{}, r.TokenHosts...), r.BlobHosts...) {
			if !validHost(h) || (!r.Local && isIPLiteral(h)) {
				return fmt.Errorf("%w: host %q", ErrPolicy, h)
			}
		}
		if (r.Username == "") != (r.Password == "") {
			return fmt.Errorf("%w: incomplete credentials for %q", ErrPolicy, r.Host)
		}
	}
	return nil
}

func isIPLiteral(hostport string) bool {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	return net.ParseIP(strings.Trim(h, "[]")) != nil
}

// Reference is a package pinned by digest. A tag, if given, is informational.
type Reference struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

func (r Reference) String() string {
	s := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	return s + "@" + r.Digest
}

// ParseReference accepts "registry/repository[:tag]@sha256:<hex>". The registry
// must be explicit: there is no default registry.
func ParseReference(s string) (Reference, error) {
	var r Reference
	name, digest, ok := strings.Cut(s, "@")
	if !ok || len(s) > 512 || !validDigest(digest) {
		return r, fmt.Errorf("%w: a reference must be pinned by sha256 digest", ErrPolicy)
	}
	registry, rest, ok := strings.Cut(name, "/")
	if !ok || !validHost(registry) || !(strings.ContainsAny(registry, ".:") || registry == "localhost") {
		return r, fmt.Errorf("%w: the registry host must be explicit", ErrPolicy)
	}
	repo, tag := rest, ""
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		repo, tag = rest[:i], rest[i+1:]
		if !tagPattern.MatchString(tag) {
			return r, fmt.Errorf("%w: tag", ErrPolicy)
		}
	}
	if !validRepository(repo) {
		return r, fmt.Errorf("%w: repository", ErrPolicy)
	}
	return Reference{Registry: registry, Repository: repo, Tag: tag, Digest: digest}, nil
}

// Allow returns the rule that approves this reference.
func (p Policy) Allow(ref Reference) (Rule, error) {
	for _, r := range p.Rules {
		if r.Host != ref.Registry {
			continue
		}
		for _, prefix := range r.Repositories {
			if strings.HasSuffix(prefix, "/") && strings.HasPrefix(ref.Repository, prefix) || prefix == ref.Repository {
				return r, nil
			}
		}
		return Rule{}, fmt.Errorf("%w: repository not approved on %s", ErrPolicy, ref.Registry)
	}
	return Rule{}, fmt.Errorf("%w: registry %s not approved", ErrPolicy, ref.Registry)
}

func validDigest(d string) bool {
	if len(d) != 71 || !strings.HasPrefix(d, "sha256:") {
		return false
	}
	for _, c := range d[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// publicIP reports whether an address may be dialed for a non-local registry.
func publicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		// Carrier-grade NAT and the IPv4-mapped/compatible forms of the above.
		(ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xc0 == 64))
}
