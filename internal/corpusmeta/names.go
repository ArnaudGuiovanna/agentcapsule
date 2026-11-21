package corpusmeta

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)
	mountPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	commit       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	idPattern    = regexp.MustCompile(`^[a-z]+_[0-9a-f]{32}$`)
)

// ValidName is the rule of a corpus's name (ADR 023 §1): 1 to 100 of
// [a-z0-9._-], starting with a letter or a digit.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// ValidMount is the rule of a mount, the directory under /corpus/ in a VM,
// and of a document's ID in the layout: 1 to 63 of [a-z0-9_-], starting with
// a letter or a digit.
func ValidMount(s string) bool { return mountPattern.MatchString(s) }

// DefaultMount is a corpus's mount when a binding names none: its name, when
// that is a valid mount; "" otherwise, and the binding must name one.
func DefaultMount(name string) string {
	if ValidMount(name) {
		return name
	}
	return ""
}

// ValidVersion is the rule of a release's version: 1 to 2,147,483,647.
func ValidVersion(v int64) bool { return v >= 1 && v <= 1<<31-1 }

// ValidCommit accepts a Git commit as 40 lowercase hex digits.
func ValidCommit(s string) bool { return commit.MatchString(s) }

// ValidUUID accepts a UUID in lowercase hex.
func ValidUUID(s string) bool { return uuidPattern.MatchString(s) }

// ValidID accepts an identifier of the platform of the given kind ("cor",
// "cbd"): the kind, '_' and 128 bits in hex.
func ValidID(kind, s string) bool {
	return len(s) == len(kind)+33 && strings.HasPrefix(s, kind+"_") && idPattern.MatchString(s)
}

// DocumentID is the ID of the document converted from the source file at
// path (relative to the corpus's path): "d" and 16 hex digits of
// sha256("agentcapsule.corpus-document.v1\0" + path). A document keeps it
// from build to build while its file keeps its path, so citations and the
// builder's cache stay valid.
func DocumentID(path string) string {
	sum := sha256.Sum256([]byte("agentcapsule.corpus-document.v1\x00" + path))
	return "d" + hex.EncodeToString(sum[:8])
}
