// Package repository describes a forge source without fetching its contents.
package repository

import (
	"errors"
	"fmt"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
	"net/url"
	"regexp"
	"strings"
)

var ErrPolicy = errors.New("invalid corpus source")

// The two forge kinds.
const (
	GitHub = "github"
	GitLab = "gitlab"
)

var (
	validHost = reference.ValidHost
	// A repository's path segment, as GitHub and GitLab allow them.
	Segment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$`)
)

// ValidRepository: owner/name on GitHub, group/[subgroup/...]name on GitLab;
// no segment that is "." or "..", no ".git" suffix, at most 20 segments.
func ValidRepository(r string, kind string) bool {
	parts := strings.Split(r, "/")
	if len(r) > 255 || len(parts) < 2 || len(parts) > 20 || (kind == GitHub && len(parts) != 2) || strings.HasSuffix(strings.ToLower(r), ".git") {
		return false
	}
	for _, p := range parts {
		if !Segment.MatchString(p) || strings.Trim(p, ".") == "" {
			return false
		}
	}
	return true
}

// Source is a corpus's repository on a forge: what a corpus's source URL
// names, https://<host>/<repository>, and its kind.
type Source struct {
	Kind       string
	Host       string
	Repository string
}

// ParseURL reads a source URL: https, a host, a repository path; no user,
// query or fragment; GitLab subgroups allowed. It checks the syntax only.
func ParseURL(kind, raw string) (Source, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 512 || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		u.RawPath != "" || !validHost(u.Host) {
		return Source{}, fmt.Errorf("%w: source URL", ErrPolicy)
	}
	s := Source{Kind: kind, Host: u.Host, Repository: strings.TrimPrefix(u.Path, "/")}
	if !s.Valid() {
		return Source{}, fmt.Errorf("%w: source URL", ErrPolicy)
	}
	return s, nil
}

func (s Source) Valid() bool {
	return (s.Kind == GitHub || s.Kind == GitLab) && validHost(s.Host) && ValidRepository(s.Repository, s.Kind)
}

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	refPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/+-]{0,254}$`)
)

// ValidCommit: 40 lowercase hexadecimal digits.
func ValidCommit(s string) bool { return commitPattern.MatchString(s) }

// ValidRef: a branch, tag or commit name the forges' APIs take in a path,
// in the subset of git check-ref-format that needs no quoting.
func ValidRef(ref string) bool {
	return refPattern.MatchString(ref) && !strings.Contains(ref, "..") && !strings.Contains(ref, "//") &&
		!strings.HasSuffix(ref, "/") && !strings.HasSuffix(ref, ".") && !strings.HasSuffix(ref, ".lock") && !strings.Contains(ref, "/.")
}
