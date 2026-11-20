package llmgateway

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"regexp"
)

// Bounds of a provider's event stream (ADR 022 §3): a line, an event's data
// (its lines joined) and its name, so that the channel frame that carries one
// event fits in 64 KiB.
const (
	maxSSELine = 64 << 10
	maxSSEData = 60 << 10
)

var (
	errSSELine = errors.New("llm stream line too long")
	errSSEData = errors.New("llm stream event too large")
	errSSEName = errors.New("llm stream event name invalid")
)

// sseName is an event's name: a short token that needs no escaping in JSON.
var sseName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// sseReader reads Server-Sent Events one at a time and keeps at most one
// event. Comment lines and the id and retry fields are read and dropped.
type sseReader struct {
	lines     *bufio.Scanner
	firstLine bool
	// alive is called at each comment line: a provider's keep-alive.
	alive func()
	data  []byte
}

func newSSEReader(r io.Reader, alive func()) *sseReader {
	lines := bufio.NewScanner(r)
	// A line, its end included; the length is checked again on each line.
	lines.Buffer(make([]byte, 0, 4096), maxSSELine+2)
	lines.Split(splitSSELine)
	return &sseReader{lines: lines, firstLine: true, alive: alive}
}

// splitSSELine splits at a line end: CRLF, LF or CR.
func splitSSELine(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		if data[i] == '\n' {
			return i + 1, data[:i], nil
		}
		if i+1 < len(data) {
			if data[i+1] == '\n' {
				return i + 2, data[:i], nil
			}
			return i + 1, data[:i], nil
		}
		if atEOF {
			return i + 1, data[:i], nil
		}
		return 0, nil, nil // a CR: is it a CRLF?
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// next returns the next event's name and data, a new slice. At the end of the
// stream it returns io.EOF; an event the stream ended inside is dropped, as
// the format says.
func (s *sseReader) next() (string, []byte, error) {
	name, has := "", false
	s.data = s.data[:0]
	for s.lines.Scan() {
		line := s.lines.Bytes()
		if len(line) > maxSSELine {
			return "", nil, errSSELine
		}
		if s.firstLine {
			s.firstLine = false
			line = bytes.TrimPrefix(line, []byte("\uFEFF"))
		}
		switch {
		case len(line) == 0:
			if has {
				return name, bytes.Clone(s.data), nil
			}
			name = ""
			continue
		case line[0] == ':':
			s.alive()
			continue
		}
		field, value := line, []byte(nil)
		if i := bytes.IndexByte(line, ':'); i >= 0 {
			field, value = line[:i], line[i+1:]
			value = bytes.TrimPrefix(value, []byte(" "))
		}
		switch string(field) {
		case "event":
			if len(value) > 0 && !sseName.Match(value) {
				return "", nil, errSSEName
			}
			name = string(value)
		case "data":
			if has {
				s.data = append(s.data, '\n')
			}
			if len(s.data)+len(value) > maxSSEData {
				return "", nil, errSSEData
			}
			s.data, has = append(s.data, value...), true
		}
	}
	if err := s.lines.Err(); errors.Is(err, bufio.ErrTooLong) {
		return "", nil, errSSELine
	} else if err != nil {
		return "", nil, err
	}
	return "", nil, io.EOF
}
