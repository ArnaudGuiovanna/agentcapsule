// Package corpussource fetches the sources of a corpus from a Git forge
// (GitHub or GitLab) as opaque bytes (ADR 023 §3 and §4). It resolves a ref
// to a commit through the forge's API, downloads the commit's archive, and
// downloads the Git LFS objects a build needs through the LFS batch API. It
// talks only to the forges an operator approved, follows at most two
// redirects and only to the hosts a rule declares, connects only to public
// addresses unless the operator allows an internal forge, and sends a
// credential only to the forge itself.
//
// The host never decodes what it fetches: it streams, counts, hashes, pads
// and concatenates bytes, and nothing else. No tar, gzip, git or other
// program runs on them (REG-007, RUN-010); even the HTTP client's
// transparent decompression is off.
package corpussource

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/repository"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
)

var (
	// ErrPolicy: no rule approves the forge or the repository, a redirect
	// leads to a host the rule does not declare, or an address is not
	// allowed. Nothing was fetched from it. Build error code policy.
	ErrPolicy = errors.New("corpus source not allowed")
	// ErrNotFound: the forge says the ref, the commit, the repository or an
	// object does not exist, or does not say whether it exists (a forge
	// answers 404 for a private repository it hides). Code not_found.
	ErrNotFound = errors.New("corpus source not found")
	// ErrDenied: the forge refused the credential, or the credential is
	// missing or disabled. Code access_denied.
	ErrDenied = errors.New("corpus source access denied")
	// ErrIntegrity: a download does not match its digest or its size.
	// Code integrity.
	ErrIntegrity = errors.New("corpus source content failed verification")
	// ErrTooLarge: the archive or the LFS objects are past their limits.
	// Code too_large.
	ErrTooLarge = errors.New("corpus source too large")
	// ErrUnavailable: the forge could not be reached or answered an error;
	// retrying later may succeed. Code unavailable after the last attempt.
	ErrUnavailable = errors.New("corpus source unavailable")
)

// The two forge kinds.
const (
	GitHub = "github"
	GitLab = "gitlab"
)

// Rule approves one forge and the repositories that may be fetched from it
// (the worker's corpus.sources.rules[], ADR 023 §3.2).
type Rule struct {
	// Host is the forge's host and optional port, as in a source URL:
	// "github.com", "gitlab.example.org".
	Host string `json:"host"`
	// Kind is github or gitlab.
	Kind string `json:"kind"`
	// APIHost serves the forge's API; default api.github.com for
	// github.com, the host otherwise.
	APIHost string `json:"api_host,omitempty"`
	// Repositories are allowed repository prefixes: "org/" allows every
	// repository under org (GitLab subgroups included), "org/name" exactly
	// that one. Compared without regard to case, as the forges do.
	Repositories []string `json:"repositories"`
	// ArchiveHosts may serve a redirected archive download, such as
	// codeload.github.com.
	ArchiveHosts []string `json:"archive_hosts,omitempty"`
	// LFSHosts may serve LFS objects, such as
	// github-cloud.githubusercontent.com.
	LFSHosts []string `json:"lfs_hosts,omitempty"`
	// Local fetches over plain HTTP and allows internal addresses, for
	// development only: production refuses a worker with such a rule. It
	// never allows link-local, unspecified, multicast or metadata addresses.
	Local bool `json:"local,omitempty"`
}

// Policy is the worker's source policy: its rules, and the internal forge
// addresses the operator allows (corpus.sources.allowed_internal_hosts), in
// the syntax of llm.allowed_internal_providers.
type Policy struct {
	Rules                []Rule
	AllowedInternalHosts []string
}

var validHost = reference.ValidHost

// apiHost is the rule's API host, its default applied.
func (r Rule) apiHost() string {
	switch {
	case r.APIHost != "":
		return r.APIHost
	case r.Kind == GitHub && r.Host == "github.com":
		return "api.github.com"
	}
	return r.Host
}

// Validate refuses rules that would widen the policy by accident.
func (p Policy) Validate() error {
	if _, err := llmgateway.ParseAllowlist(p.AllowedInternalHosts); err != nil {
		return fmt.Errorf("%w: allowed_internal_hosts: %v", ErrPolicy, err)
	}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !validHost(r.Host) || seen[r.Host] || (r.Kind != GitHub && r.Kind != GitLab) || len(r.Repositories) == 0 || len(r.Repositories) > 100 {
			return fmt.Errorf("%w: rule for %q", ErrPolicy, r.Host)
		}
		seen[r.Host] = true
		hosts := append(append([]string{r.Host, r.apiHost()}, r.ArchiveHosts...), r.LFSHosts...)
		if len(hosts) > 34 {
			return fmt.Errorf("%w: too many hosts for %q", ErrPolicy, r.Host)
		}
		for _, h := range hosts {
			if !validHost(h) || (!r.Local && isIPLiteral(h)) {
				return fmt.Errorf("%w: host %q", ErrPolicy, h)
			}
		}
		for _, prefix := range r.Repositories {
			name := strings.TrimSuffix(prefix, "/")
			if name == prefix && !repository.ValidRepository(name, r.Kind) {
				return fmt.Errorf("%w: repository %q", ErrPolicy, prefix)
			}
			for _, part := range strings.Split(name, "/") {
				if !repository.ValidSegment(part) {
					return fmt.Errorf("%w: repository prefix %q", ErrPolicy, prefix)
				}
			}
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

type Source = repository.Source

func ParseURL(kind, raw string) (Source, error) {
	src, err := repository.ParseURL(kind, raw)
	if err != nil {
		return Source{}, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	return src, nil
}

// Allow returns the rule that approves this source: the rule of its host and
// kind, with a repository prefix that covers it.
func (p Policy) Allow(s Source) (Rule, error) {
	if !s.Valid() {
		return Rule{}, fmt.Errorf("%w: source", ErrPolicy)
	}
	for _, r := range p.Rules {
		if r.Host != s.Host {
			continue
		}
		if r.Kind != s.Kind {
			return Rule{}, fmt.Errorf("%w: the forge %s is not of kind %s", ErrPolicy, s.Host, s.Kind)
		}
		repo := strings.ToLower(s.Repository)
		for _, prefix := range r.Repositories {
			prefix = strings.ToLower(prefix)
			if strings.HasSuffix(prefix, "/") && strings.HasPrefix(repo, prefix) || prefix == repo {
				return r, nil
			}
		}
		return Rule{}, fmt.Errorf("%w: repository not approved on %s", ErrPolicy, s.Host)
	}
	return Rule{}, fmt.Errorf("%w: forge %s not approved", ErrPolicy, s.Host)
}

// AllowsHost reports whether a rule of the policy names host for kind: the
// worker refuses a build whose credential's host matches no rule.
func (p Policy) AllowsHost(kind, host string) bool {
	for _, r := range p.Rules {
		if r.Host == host && r.Kind == kind {
			return true
		}
	}
	return false
}

// Token is a forge credential, in memory only while a fetch needs it. It
// formats as "[redacted]", so that no log line or error can show it.
type Token string

func (Token) String() string   { return "[redacted]" }
func (Token) GoString() string { return "[redacted]" }
