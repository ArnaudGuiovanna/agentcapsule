package capsuleprotocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Streams on the platform channel (ADR 022). A stream route answers NDJSON:
// one strict JSON object per line, each line at most MaxStreamFrameBytes with
// its newline. The output stream of a working invocation (OutputStreamPath)
// is full duplex: the harness writes its frames in the request body while the
// platform writes its control frames in the answer.
const (
	MaxStreamFrameBytes = 64 << 10
	// StreamIdleTimeout is the default bound between two frames of a stream.
	StreamIdleTimeout = 60 * time.Second
	// MaxOutputStreamIdle is the longest idle bound a worker may set for an
	// output stream (output_streams.idle_timeout). The guest's bridge waits
	// that long, so that the host's own bound decides.
	MaxOutputStreamIdle = 300 * time.Second
	OutputStreamPath    = "/v1/invocations/stream"
	// outputStreamOpenTimeout bounds the wait for the open frame.
	outputStreamOpenTimeout = 5 * time.Second
	ndjsonType              = "application/x-ndjson"
)

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

var closedReasons = []string{StreamDone, StreamTerminal, StreamExpired, StreamReset, StreamRevoked, StreamInvalid, StreamTruncated, StreamIdle, StreamUnavailable}

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
	b, err := encodeFrame(f)
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

// encodeFrame encodes v as one line, newline included, refusing a line over
// MaxStreamFrameBytes.
func encodeFrame(v any) ([]byte, error) {
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

// The harness's frames, as they come: each type decoded strictly on its own.
type openFrame struct {
	Type        string   `json:"type"`
	Protocol    string   `json:"protocol"`
	Identity    Identity `json:"identity"`
	OperationID string   `json:"operation_id"`
	Attempt     *int     `json:"attempt,omitempty"`
}
type deltaFrame struct {
	Type string `json:"type"`
	Seq  int64  `json:"seq"`
	Text string `json:"text"`
}
type stepFrame struct {
	Type  string  `json:"type"`
	Seq   int64   `json:"seq"`
	Step  string  `json:"step"`
	State string  `json:"state"`
	Label *string `json:"label,omitempty"`
}
type bareFrame struct {
	Type string `json:"type"`
}

// frameType reads the type of a line, which must be valid UTF-8 JSON.
func frameType(line []byte) (string, error) {
	var t bareFrame
	if !utf8.Valid(line) || json.Unmarshal(line, &t) != nil || t.Type == "" {
		return "", ErrProtocol
	}
	return t.Type, nil
}

// parseOpen decodes the first line of an output stream.
func parseOpen(line []byte) (openFrame, error) {
	var o openFrame
	if kind, err := frameType(line); err != nil || kind != "open" {
		return o, ErrProtocol
	}
	if err := decode(bytes.NewReader(line), &o); err != nil {
		return o, err
	}
	if o.OperationID == "" || len(o.OperationID) > 100 || !utf8.ValidString(o.OperationID) || o.Attempt != nil && *o.Attempt < 1 {
		return o, ErrProtocol
	}
	return o, nil
}

// parseHarnessFrame decodes a line after the first: a delta, a step, or the
// close frame (closing true).
func parseHarnessFrame(line []byte) (f OutputFrame, closing bool, err error) {
	kind, err := frameType(line)
	if err != nil {
		return f, false, err
	}
	switch kind {
	case "delta":
		var d deltaFrame
		if err = decode(bytes.NewReader(line), &d); err != nil {
			return f, false, err
		}
		f = OutputFrame{Type: d.Type, Seq: d.Seq, Text: d.Text}
	case "step":
		var s stepFrame
		if err = decode(bytes.NewReader(line), &s); err != nil {
			return f, false, err
		}
		if s.Label != nil && *s.Label == "" {
			return f, false, ErrProtocol
		}
		f = OutputFrame{Type: s.Type, Seq: s.Seq, Step: s.Step, State: s.State}
		if s.Label != nil {
			f.Label = *s.Label
		}
	case "close":
		var c bareFrame
		if err = decode(bytes.NewReader(line), &c); err != nil {
			return f, false, err
		}
		return f, true, nil
	default:
		return f, false, ErrProtocol
	}
	return f, false, f.Validate()
}

// The platform's frames on an output stream.
type openedFrame struct {
	Type     string   `json:"type"`
	Protocol string   `json:"protocol"`
	Identity Identity `json:"identity"`
	Attempt  int      `json:"attempt"`
	Seq      int64    `json:"seq"`
}
type ackFrame struct {
	Type string `json:"type"`
	Seq  int64  `json:"seq"`
}
type closedFrame struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// ControlFrame is a frame the platform sends on an output stream: opened
// (Identity, Attempt, Seq), ack (Seq), cancel, or closed (Reason).
type ControlFrame struct {
	Type     string
	Identity Identity
	Attempt  int
	Seq      int64
	Reason   string
}

// parseControlFrame decodes one line of the platform's answer strictly.
func parseControlFrame(line []byte) (ControlFrame, error) {
	kind, err := frameType(line)
	if err != nil {
		return ControlFrame{}, err
	}
	switch kind {
	case "opened":
		var o openedFrame
		if err = decode(bytes.NewReader(line), &o); err != nil || o.Protocol != Version || o.Attempt < 1 || o.Seq < 0 {
			return ControlFrame{}, ErrProtocol
		}
		return ControlFrame{Type: kind, Identity: o.Identity, Attempt: o.Attempt, Seq: o.Seq}, nil
	case "ack":
		var a ackFrame
		if err = decode(bytes.NewReader(line), &a); err != nil || a.Seq < 1 {
			return ControlFrame{}, ErrProtocol
		}
		return ControlFrame{Type: kind, Seq: a.Seq}, nil
	case "cancel":
		var c bareFrame
		if err = decode(bytes.NewReader(line), &c); err != nil {
			return ControlFrame{}, ErrProtocol
		}
		return ControlFrame{Type: kind}, nil
	case "closed":
		var c closedFrame
		if err = decode(bytes.NewReader(line), &c); err != nil || !slices.Contains(closedReasons, c.Reason) {
			return ControlFrame{}, ErrProtocol
		}
		return ControlFrame{Type: kind, Reason: c.Reason}, nil
	}
	return ControlFrame{}, ErrProtocol
}

// controlSequence checks the order of the platform's frames: opened first,
// then acks that never go back, cancel at most once, closed last.
type controlSequence struct {
	opened, canceled, closed bool
	identity                 Identity
	acked                    int64
}

func (s *controlSequence) next(f ControlFrame) error {
	switch {
	case s.closed:
		return ErrProtocol
	case !s.opened:
		if f.Type != "opened" || f.Identity != s.identity {
			return ErrProtocol
		}
		s.opened, s.acked = true, f.Seq
	case f.Type == "ack":
		if f.Seq < s.acked {
			return ErrProtocol
		}
		s.acked = f.Seq
	case f.Type == "cancel" && !s.canceled:
		s.canceled = true
	case f.Type == "closed":
		s.closed = true
	default:
		return ErrProtocol
	}
	return nil
}

// errFrameTooLarge: a line over MaxStreamFrameBytes, or without its newline.
var errFrameTooLarge = errors.Join(ErrProtocol, errors.New("stream frame too large"))

// frameReader reads the lines of a stream, each at most MaxStreamFrameBytes
// with its newline. deadline, when set, is pushed before each line.
type frameReader struct {
	r        *bufio.Reader
	deadline func(time.Time) error
}

func newFrameReader(r io.Reader, deadline func(time.Time) error) *frameReader {
	return &frameReader{r: bufio.NewReaderSize(r, MaxStreamFrameBytes), deadline: deadline}
}

// next returns the next line without its newline, waiting at most idle.
func (f *frameReader) next(idle time.Duration) ([]byte, error) {
	if f.deadline != nil {
		_ = f.deadline(time.Now().Add(idle))
	}
	line, err := f.r.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, errFrameTooLarge
	case err == io.EOF && len(line) > 0:
		return nil, errFrameTooLarge
	case err != nil:
		return nil, err
	}
	return bytes.Clone(line[:len(line)-1]), nil
}

// frameWriter writes the lines of a stream and flushes each one. Its writes
// are serialized; deadline, when set, is pushed before each line.
type frameWriter struct {
	mu       sync.Mutex
	w        io.Writer
	flush    func() error
	deadline func(time.Time) error
	timeout  time.Duration
}

func (f *frameWriter) write(v any) error {
	b, err := encodeFrame(v)
	if err != nil {
		return err
	}
	return f.writeLine(b)
}

// writeLine writes one line, its newline included.
func (f *frameWriter) writeLine(line []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deadline != nil {
		_ = f.deadline(time.Now().Add(f.timeout))
	}
	if _, err := f.w.Write(line); err != nil {
		return err
	}
	if f.flush != nil {
		return f.flush()
	}
	return nil
}

// isTimeout reports a passed read or write deadline.
func isTimeout(err error) bool {
	var n net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &n) && n.Timeout()
}
