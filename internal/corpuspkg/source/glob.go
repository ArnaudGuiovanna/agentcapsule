package source

import (
	"errors"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidPattern checks an include or exclude glob: a relative path whose
// elements are "**" (any number of elements, none included) or a pattern of
// path.Match ('*', '?', '[...]' within one element). No leading '/', no '.'
// or '..' element, no empty element, no backslash, at most 256 bytes.
func ValidPattern(p string) error {
	if p == "" || len(p) > 256 || !utf8.ValidString(p) || strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return errors.New("a glob of 1 to 256 bytes, without control characters")
	}
	if strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') {
		return errors.New("a glob relative to the corpus's path, with '/' between elements")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("no empty, '.' or '..' element")
		}
		if _, err := path.Match(part, ""); err != nil {
			return errors.New("malformed glob element " + part)
		}
	}
	return nil
}

// Match reports whether a valid pattern matches the file at name, a clean
// relative path, or one of the directories that hold it: "courses" and
// "courses/**" both match courses/chap1.pdf.
func Match(pattern, name string) bool {
	// Matching a directory that holds the file is matching pattern/**.
	pat, parts := append(strings.Split(pattern, "/"), "**"), strings.Split(name, "/")
	// next[j]: the pattern's elements after i match parts[j:]. Each pair of
	// positions is decided once, so a glob of many "**" stays linear in
	// each.
	next := make([]bool, len(parts)+1)
	next[len(parts)] = true
	cur := make([]bool, len(parts)+1)
	for i := len(pat) - 1; i >= 0; i-- {
		for j := len(parts); j >= 0; j-- {
			if pat[i] == "**" {
				cur[j] = next[j] || j < len(parts) && cur[j+1]
				continue
			}
			ok := false
			if j < len(parts) {
				ok, _ = path.Match(pat[i], parts[j])
			}
			cur[j] = ok && next[j+1]
		}
		next, cur = cur, next
	}
	return next[0]
}
