// Package reference parses the reference of a harness package pinned by
// digest, "registry/repository[:tag]@sha256:<hex>", and the names it is made
// of. It is syntax only: it connects to nothing and reads no package, so the
// API, which records import requests, links it without the importer
// (package ociregistry) and the image checks behind it.
package reference

import (
	"errors"
	"regexp"
	"strings"
)

var (
	hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$`)
	repoPart    = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
	tagPattern  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// ValidHost: a registry host, with an optional port.
func ValidHost(h string) bool { return len(h) <= 255 && hostPattern.MatchString(h) }

// ValidRepository: lowercase path components separated by "/".
func ValidRepository(r string) bool {
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

// ValidTag: an OCI tag.
func ValidTag(t string) bool { return tagPattern.MatchString(t) }

// ValidDigest: "sha256:" and 64 lowercase hexadecimal digits.
func ValidDigest(d string) bool {
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

// Parse accepts "registry/repository[:tag]@sha256:<hex>". The registry must
// be explicit: there is no default registry.
func Parse(s string) (Reference, error) {
	var r Reference
	name, digest, ok := strings.Cut(s, "@")
	if !ok || len(s) > 512 || !ValidDigest(digest) {
		return r, errors.New("a reference must be pinned by sha256 digest")
	}
	registry, rest, ok := strings.Cut(name, "/")
	if !ok || !ValidHost(registry) || !(strings.ContainsAny(registry, ".:") || registry == "localhost") {
		return r, errors.New("the registry host must be explicit")
	}
	repo, tag := rest, ""
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		repo, tag = rest[:i], rest[i+1:]
		if !ValidTag(tag) {
			return r, errors.New("tag")
		}
	}
	if !ValidRepository(repo) {
		return r, errors.New("repository")
	}
	return Reference{Registry: registry, Repository: repo, Tag: tag, Digest: digest}, nil
}
