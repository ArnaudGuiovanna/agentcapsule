package wire

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxStreamFrameBytes = 64 << 10

// Why an output stream closes: the reason of its closed frame.
const (
	StreamDone        = "done"
	StreamTerminal    = "terminal"
	StreamExpired     = "expired"
	StreamReset       = "reset"
	StreamRevoked     = "revoked"
	StreamInvalid     = "invalid"
	StreamTruncated   = "truncated"
	StreamIdle        = "idle"
	StreamUnavailable = "unavailable"
	// StreamCanceled is no closed reason: the requester canceled the
	// invocation, or its agent is being deleted. The platform sends cancel,
	// then closed with StreamTerminal.
	StreamCanceled = "canceled"
)

// The states of a step frame.
const (
	StepStarted = "started"
	StepDone    = "done"
	StepFailed  = "failed"
)

var stepName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// OutputFrame is one frame of an output stream that the platform stores: a
// delta of text, or a step. Seq is per attempt, from 1, without a gap.
type OutputFrame struct {
	Type  string `json:"type"`
	Seq   int64  `json:"seq"`
	Text  string `json:"text,omitempty"`
	Step  string `json:"step,omitempty"`
	State string `json:"state,omitempty"`
	Label string `json:"label,omitempty"`
}

// Validate accepts a delta with non-empty UTF-8 text without NUL, or a step
// with a lower-case name, a known state and an optional label of at most 256
// bytes without control characters.
func (f OutputFrame) Validate() error {
	if f.Seq < 1 {
		return ErrProtocol
	}
	switch f.Type {
	case "delta":
		if f.Text == "" || !utf8.ValidString(f.Text) || strings.ContainsRune(f.Text, 0) || f.Step != "" || f.State != "" || f.Label != "" {
			return ErrProtocol
		}
	case "step":
		if f.Text != "" || !stepName.MatchString(f.Step) || !slices.Contains([]string{StepStarted, StepDone, StepFailed}, f.State) ||
			len(f.Label) > 256 || !utf8.ValidString(f.Label) || strings.IndexFunc(f.Label, unicode.IsControl) >= 0 {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}

// Encode is the frame's stored form: compact JSON, without HTML escapes and
// without a newline. A frame and its newline fit in MaxStreamFrameBytes.
func (f OutputFrame) Encode() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	b, err := EncodeFrame(f)
	if err != nil {
		return nil, err
	}
	return b[:len(b)-1], nil
}

// EncodeOutputChunk is a chunk's plaintext: the JSON array of its frames, in
// order, each in its stored form.
func EncodeOutputChunk(frames []OutputFrame) ([]byte, error) {
	if len(frames) == 0 {
		return nil, ErrProtocol
	}
	out := []byte{'['}
	for i, f := range frames {
		b, err := f.Encode()
		if err != nil {
			return nil, err
		}
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, b...)
	}
	return append(out, ']'), nil
}

// EncodeFrame encodes v as one line, newline included, refusing a line over
// MaxStreamFrameBytes.
func EncodeFrame(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, ErrProtocol
	}
	if b.Len() > MaxStreamFrameBytes {
		return nil, ErrProtocol
	}
	return b.Bytes(), nil
}
