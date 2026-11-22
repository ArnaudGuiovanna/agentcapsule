package wire

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// ContentPart is one part of a message: text, of content type text/plain, or
// a JSON value, of content type application/json.
//
//	{"type":"text","text":"Summarize this"}
//	{"type":"json","json":{"rows":[1,2]}}
//
// A text part encodes exactly as it did before JSON parts existed. Parts
// compare with ==, as they did.
type ContentPart struct {
	Type string    `json:"type"`
	Text string    `json:"text,omitempty"`
	JSON JSONValue `json:"json,omitempty"`
}

// JSONValue is a JSON value kept as its encoded text, so that a part stays
// comparable. Validation (compactJSON) is the content checks' job.
type JSONValue string

func (v JSONValue) MarshalJSON() ([]byte, error) {
	if v == "" {
		return []byte("null"), nil
	}
	return []byte(v), nil
}

func (v *JSONValue) UnmarshalJSON(b []byte) error {
	*v = JSONValue(b)
	return nil
}

// TextContent is the former name of ContentPart, kept for existing callers.
type TextContent = ContentPart

const (
	// MaxContentParts bounds the parts of one message.
	MaxContentParts = 32
	// MaxMessageContentBytes bounds the text of a message plus the compact
	// form of its JSON values (invocations, results, owner messages).
	MaxMessageContentBytes = 32 * 1024
	// MaxPeerPayloadBytes bounds the encoded payload of a request or reply
	// between agents, in its text form (TextOnly).
	MaxPeerPayloadBytes = 64 * 1024
	// MaxJSONDepth bounds the nesting of arrays and objects in a JSON part.
	MaxJSONDepth = 32
)

// size validates one part and returns what it counts toward a message's
// bound: the bytes of its text, or of its value's compact form.
func (c ContentPart) size() (int, error) {
	switch c.Type {
	case "text":
		if c.JSON != "" || !utf8.ValidString(c.Text) || strings.TrimSpace(c.Text) == "" || strings.ContainsRune(c.Text, 0) {
			return 0, ErrProtocol
		}
		return len(c.Text), nil
	case "json":
		compact, err := compactJSON(c.JSON)
		if err != nil || c.Text != "" {
			return 0, ErrProtocol
		}
		return len(compact), nil
	}
	return 0, ErrProtocol
}

// compactJSON is the value's canonical text: the JSON without insignificant
// whitespace. The value is one JSON value other than null, in UTF-8, at most
// MaxJSONDepth deep.
func compactJSON(v JSONValue) (string, error) {
	raw := []byte(v)
	if len(raw) == 0 || !utf8.Valid(raw) || !json.Valid(raw) || !shallow(raw) {
		return "", ErrProtocol
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil || b.String() == "null" {
		return "", ErrProtocol
	}
	return b.String(), nil
}

// shallow reports whether valid JSON nests at most MaxJSONDepth levels.
func shallow(raw []byte) bool {
	depth, quoted, escaped := 0, false, false
	for _, c := range raw {
		switch {
		case escaped:
			escaped = false
		case quoted:
			escaped, quoted = c == '\\', c != '"'
		case c == '"':
			quoted = true
		case c == '[' || c == '{':
			if depth++; depth > MaxJSONDepth {
				return false
			}
		case c == ']' || c == '}':
			depth--
		}
	}
	return true
}

// validParts checks 1 to MaxContentParts valid parts whose sizes add up to at
// most limit bytes (no limit when limit is 0).
func validParts(parts []ContentPart, limit int) error {
	if len(parts) < 1 || len(parts) > MaxContentParts {
		return ErrProtocol
	}
	total := 0
	for _, c := range parts {
		n, err := c.size()
		if err != nil {
			return err
		}
		total += n
	}
	if limit > 0 && total > limit {
		return ErrProtocol
	}
	return nil
}

// HasJSON reports whether any part is a JSON value.
func HasJSON(parts []ContentPart) bool {
	for _, c := range parts {
		if c.Type == "json" {
			return true
		}
	}
	return false
}

// TextOnly gives each JSON part as a text part holding the value's compact
// form; text parts are kept. It returns parts itself when there is no JSON
// part. This is what a harness that does not accept JSON content receives.
func TextOnly(parts []ContentPart) []ContentPart {
	if !HasJSON(parts) {
		return parts
	}
	out := make([]ContentPart, len(parts))
	for i, c := range parts {
		out[i] = c
		if c.Type == "json" {
			text, err := compactJSON(c.JSON)
			if err != nil {
				text = string(c.JSON) // invalid anyway: refused downstream
			}
			out[i] = ContentPart{Type: "text", Text: text}
		}
	}
	return out
}
