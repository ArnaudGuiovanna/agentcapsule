package corpusmeta

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind is a source file's type, from its extension (the report's kind, ADR
// 023 §2.4).
type Kind string

const (
	KindMarkdown Kind = "markdown"
	KindText     Kind = "text"
	KindPDF      Kind = "pdf"
	KindDOCX     Kind = "docx"
	KindPPTX     Kind = "pptx"
	KindODT      Kind = "odt"
	KindXLSX     Kind = "xlsx"
	KindCSV      Kind = "csv"
	KindImage    Kind = "image"
	KindAudio    Kind = "audio"
	KindVideo    Kind = "video"
	KindOther    Kind = "other"
)

// Kinds lists every kind, other last.
var Kinds = []Kind{KindMarkdown, KindText, KindPDF, KindDOCX, KindPPTX, KindODT, KindXLSX, KindCSV, KindImage,
	KindAudio, KindVideo, KindOther}

// Text reports whether s is 1 to max characters of valid UTF-8, not only
// spaces, without control characters.
func Text(s string, max int) bool {
	return utf8.ValidString(s) && strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= max &&
		strings.IndexFunc(s, unicode.IsControl) < 0
}

// ValidAlias is the platform channel's rule for an LLM alias: 1 to 100
// bytes of UTF-8, without spaces, tabs, line breaks or NUL.
func ValidAlias(a string) bool {
	return a != "" && len(a) <= 100 && utf8.ValidString(a) && !strings.ContainsAny(a, " \t\r\n\x00")
}

// ValidPath reports whether p is a clean relative path inside the corpus:
// no leading '/', no '.' or '..' element, no empty element, no backslash,
// printable UTF-8, at most 1,024 bytes.
func ValidPath(p string) bool {
	if p == "" || len(p) > 1024 || !utf8.ValidString(p) || strings.IndexFunc(p, unicode.IsControl) >= 0 ||
		strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') || path.Clean(p) != p {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}
