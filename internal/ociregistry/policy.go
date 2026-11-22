// Package ociregistry fetches and publishes harness packages over the OCI
// distribution API. It talks only to registries an operator approved, follows
// redirects only to approved hosts, never connects to private addresses unless
// a registry is explicitly marked local, never to link-local or cloud
// metadata addresses at all, and verifies every byte by digest.
package ociregistry

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/addrpolicy"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
)

var (
	// ErrPolicy: the reference, registry, repository or a redirect target is
	// not allowed. Nothing was fetched from it.
	ErrPolicy = errors.New("registry reference not allowed")
	// ErrUnavailable: the registry could not be reached or answered an error;
	// retrying later may succeed.
	ErrUnavailable = errors.New("registry unavailable")
	// ErrDenied: the registry or its token service refused access. The
	// repository is private and the credentials are missing or wrong, or it does
	// not exist: registries often do not say which. Retrying will not help until
	// the operator changes the credentials or the reference.
	ErrDenied = errors.New("registry access denied")
	// ErrSignature: the rule requires a signature by a trusted publisher key
	// and none of the signatures attached to the package qualifies.
	ErrSignature = errors.New("no trusted signature")
	// ErrNotFound: the registry answered that the manifest or a blob does not exist.
	ErrNotFound = errors.New("registry content not found")
	// ErrIntegrity: the registry served content that does not match its digest,
	// size or declared media type.
	ErrIntegrity = errors.New("registry content failed verification")
	// ErrUnsigned: production requires signatures, and a rule trusts no
	// publisher key without saying allow_unsigned (L-16). It wraps in a
	// policy error.
	ErrUnsigned = errors.New("signatures are required: the rule trusts no publisher key and does not say allow_unsigned")
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
	// Local allows plain HTTP and internal addresses (loopback, private,
	// carrier-grade NAT). Only for a registry on the operator's own network,
	// in development; never for a public one. It never allows link-local,
	// "this network" or cloud metadata addresses.
	Local bool `json:"local,omitempty"`
	// Username and Password authenticate to a private registry. They come
	// from operator configuration, are never logged or returned, and are sent
	// only in answer to a challenge: as Basic credentials to the registry
	// itself, or to an approved token service in exchange for a bearer token.
	// They never follow a redirect to another host (a blob CDN).
	Username string `json:"-"`
	Password string `json:"-"`
	// Keys, when set, are the publishers trusted for this registry: every
	// package imported through the rule must carry a signature by one of them.
	Keys []PublisherKey `json:"-"`
	// AllowUnsigned is the explicit opt-out of a rule that trusts no key:
	// in production (Policy.SignaturesByDefault) only such a rule imports
	// unsigned packages. Strict mode refuses it, and so does a rule that
	// also trusts keys.
	AllowUnsigned bool `json:"allow_unsigned,omitempty"`
}

// Policy is the installation's registry trust policy.
type Policy struct {
	Rules []Rule
	// RequireSignatures is strict mode: every rule must trust publisher keys,
	// so no unsigned package can be imported.
	RequireSignatures bool
	// SignaturesByDefault is production's default (L-16): a rule must trust
	// publisher keys, or say AllowUnsigned. Without it (development), a rule
	// without keys imports unsigned packages.
	SignaturesByDefault bool
}

// The syntax of references and their names is package reference's.
var (
	validHost       = reference.ValidHost
	validRepository = reference.ValidRepository
	validDigest     = reference.ValidDigest
)

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
		if p.RequireSignatures && len(r.Keys) == 0 {
			return fmt.Errorf("%w: signatures are required but %q trusts no publisher key", ErrPolicy, r.Host)
		}
		if r.AllowUnsigned && (len(r.Keys) > 0 || p.RequireSignatures) {
			return fmt.Errorf("%w: %q says allow_unsigned, but trusts publisher keys or strict mode is on", ErrPolicy, r.Host)
		}
		if p.SignaturesByDefault && len(r.Keys) == 0 && !r.AllowUnsigned {
			return fmt.Errorf("%w: %w: %q", ErrPolicy, ErrUnsigned, r.Host)
		}
		if (r.Username == "") != (r.Password == "") || !validCredential(r.Username, 256) || !validCredential(r.Password, 4096) ||
			strings.Contains(r.Username, ":") {
			return fmt.Errorf("%w: invalid credentials for %q", ErrPolicy, r.Host)
		}
	}
	return nil
}

// validCredential: printable ASCII without spaces, so it cannot split or
// inject a header. Empty means none.
func validCredential(v string, max int) bool {
	if len(v) > max {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] > '~' {
			return false
		}
	}
	return true
}

func isIPLiteral(hostport string) bool {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	return net.ParseIP(strings.Trim(h, "[]")) != nil
}

// Reference is a package pinned by digest. A tag, if given, is informational.
type Reference = reference.Reference

// ParseReference accepts "registry/repository[:tag]@sha256:<hex>". The registry
// must be explicit: there is no default registry.
func ParseReference(s string) (Reference, error) {
	r, err := reference.Parse(s)
	if err != nil {
		return Reference{}, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	return r, nil
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

// allowsAddress is the rule's address policy. The client applies it to every
// connection, token requests and redirects included, after DNS resolution.
// The classes are the model gateway's (internal/addrpolicy): a public
// address is always allowed; an internal one (loopback, private, carrier-grade
// NAT and the other reserved ranges) only for a local rule; an unspecified,
// multicast, link-local, "this network" or cloud metadata address never, even
// for a local rule. IPv4-mapped and NAT64 addresses count as the IPv4 address
// they carry.
func (r Rule) allowsAddress(a netip.Addr) bool {
	switch addrpolicy.Classify(a) {
	case addrpolicy.Public:
		return true
	case addrpolicy.Internal:
		return r.Local
	}
	return false
}
