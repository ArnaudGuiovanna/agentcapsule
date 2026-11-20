package capsuleprotocol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"
)

// OutputStreamAPI is optional on a PlatformAPI: the host serves the output
// stream of a working invocation (ADR 022 §5).
type OutputStreamAPI interface {
	// OpenOutputStream runs the opening (ADR 022 §5.4) and returns the bound
	// stream. attempt is 0 when the harness names none. A refusal is a
	// *PlatformError.
	OpenOutputStream(ctx context.Context, operationID string, attempt int) (OutputStream, error)
}

// OutputStream is an open output stream, bound to its invocation's attempt.
type OutputStream interface {
	Attempt() int
	// LastSeq is the last seq stored for the attempt, 0 if none.
	LastSeq() int64
	// Closing is the reason the stream closes as soon as it opens (reset,
	// truncated), or "".
	Closing() string
	// Append commits one chunk (ADR 022 §5.6) and returns the reason to
	// close, or "": a closed reason, or StreamCanceled. The frames it does
	// not store are its own to count.
	Append(ctx context.Context, frames []OutputFrame) (closeReason string, err error)
	// Signals reports a cancellation or an outcome of the invocation between
	// chunks, once.
	Signals() <-chan StreamSignal
	// Close ends the stream. reason is its closed reason ("" when the harness
	// went away without one); dropped counts the frames received and never
	// given to Append: those still buffered when it closed.
	Close(reason string, dropped int)
}

// StreamSignal is why an open stream must close: a closed reason, or
// StreamCanceled.
type StreamSignal struct{ Reason string }

// OutputStreamSettings are the host's bounds of an output stream: a chunk
// is committed when its frames reach CoalesceBytes, CoalesceWindow after its
// oldest frame, or at close; the stream closes idle after IdleTimeout
// without a frame from the harness.
type OutputStreamSettings struct {
	CoalesceWindow time.Duration
	CoalesceBytes  int
	IdleTimeout    time.Duration
}

// DefaultOutputStreamSettings are output_streams' defaults.
var DefaultOutputStreamSettings = OutputStreamSettings{CoalesceWindow: 150 * time.Millisecond, CoalesceBytes: 4096, IdleTimeout: StreamIdleTimeout}

// Valid holds the bounds of the worker's settings.
func (s OutputStreamSettings) Valid() bool {
	return s.CoalesceWindow >= 10*time.Millisecond && s.CoalesceWindow <= time.Second && s.CoalesceBytes >= 512 && s.CoalesceBytes <= 65536 &&
		s.IdleTimeout >= 10*time.Second && s.IdleTimeout <= MaxOutputStreamIdle
}

// OutputStreamTuning is optional on an OutputStreamAPI: its settings, else
// DefaultOutputStreamSettings.
type OutputStreamTuning interface {
	OutputStreamSettings() OutputStreamSettings
}

// streamOpener is the guest's bridge: it opens a stream route on the host,
// whose refusal is a *PlatformError.
type streamOpener interface {
	openStream(ctx context.Context, path string, body io.Reader) (*http.Response, error)
}

// streamRefusalStatus is the HTTP status of a refused stream opening.
func streamRefusalStatus(code string) int {
	switch code {
	case "unauthorized", "capability_denied":
		return http.StatusForbidden
	case "not_found":
		return http.StatusNotFound
	case "invalid":
		return http.StatusBadRequest
	case "transition", "expired", "conflict":
		return http.StatusConflict
	}
	return http.StatusServiceUnavailable
}

// serveOutputStream serves POST /v1/invocations/stream, after the handler's
// authentication and slot: the stream holds the slot for its whole life. The
// first line must be the open frame, within 5 seconds. On the host, the
// capability is checked once, then the opening; the stream then runs outside
// the admission. In the guest, the stream is relayed to the host.
func (p *platformHandler) serveOutputStream(w http.ResponseWriter, r *http.Request) {
	refuse := func(code string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(streamRefusalStatus(code))
		_ = json.NewEncoder(w).Encode(platformResponse{Protocol: Version, Identity: p.id, Code: code})
	}
	if r.Method != http.MethodPost {
		refuse("not_found")
		return
	}
	rc := http.NewResponseController(w)
	// The channel is HTTP/1.1: without full duplex, Go's server would not let
	// the handler answer while it still reads the request body.
	if err := rc.EnableFullDuplex(); err != nil {
		refuse("unavailable")
		return
	}
	in := newFrameReader(r.Body, rc.SetReadDeadline)
	line, err := in.next(outputStreamOpenTimeout)
	if err != nil {
		refuse("invalid")
		return
	}
	open, err := parseOpen(line)
	if err != nil {
		refuse("invalid")
		return
	}
	if open.Protocol != Version || open.Identity != p.id {
		refuse("unauthorized")
		return
	}
	ctx := r.Context()
	if gate, ok := p.api.(CapabilityAPI); ok {
		check, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = gate.RequireCapability(check, capability.StreamOutput)
		cancel()
		if err != nil {
			refuse(safePlatformCode(err))
			return
		}
	}
	if host, ok := p.api.(streamOpener); ok {
		p.relayOutputStream(ctx, w, rc, in, line, host)
		return
	}
	api, ok := p.api.(OutputStreamAPI)
	if !ok {
		refuse("unavailable")
		return
	}
	attempt := 0
	if open.Attempt != nil {
		attempt = *open.Attempt
	}
	opening, cancel := context.WithTimeout(ctx, 15*time.Second)
	stream, err := api.OpenOutputStream(opening, open.OperationID, attempt)
	cancel()
	if err != nil {
		refuse(safePlatformCode(err))
		return
	}
	settings := DefaultOutputStreamSettings
	if t, ok := p.api.(OutputStreamTuning); ok && t.OutputStreamSettings().Valid() {
		settings = t.OutputStreamSettings()
	}
	w.Header().Set("Content-Type", ndjsonType)
	w.Header().Set("Cache-Control", "no-store")
	out := &frameWriter{w: w, flush: rc.Flush, deadline: rc.SetWriteDeadline, timeout: settings.IdleTimeout + 5*time.Second}
	_ = rc.SetWriteDeadline(time.Now().Add(out.timeout))
	w.WriteHeader(http.StatusOK)
	stream.Close(runOutputStream(ctx, p.id, stream, in, out, settings))
}

// harnessLine is one line the harness sent after open, read and checked.
type harnessLine struct {
	frame   OutputFrame
	size    int
	closing bool
	err     error
}

// readHarness reads and checks the harness's frames until close or an
// error, each within idle: strict, at most 64 KiB, seq following last.
func readHarness(ctx context.Context, in *frameReader, lines chan<- harnessLine, idle time.Duration, last int64) {
	for {
		var l harnessLine
		line, err := in.next(idle)
		if err != nil {
			l.err = err
		} else if l.frame, l.closing, err = parseHarnessFrame(line); err != nil || !l.closing && l.frame.Seq != last+1 {
			l.err = ErrProtocol
		} else if !l.closing {
			last, l.size = l.frame.Seq, len(line)+1
		}
		select {
		case lines <- l:
		case <-ctx.Done():
			return
		}
		if l.err != nil || l.closing {
			return
		}
	}
}

// runOutputStream is the host's side of an open stream: it writes opened,
// coalesces the harness's frames into chunks, acknowledges each committed
// one, and closes on the harness's close, an outcome, a cancellation, a
// refused chunk, an invalid or a late frame, or the worker's end. It
// returns the closed reason ("" when the harness went away) and the frames
// it dropped without giving them to Append.
func runOutputStream(ctx context.Context, id Identity, s OutputStream, in *frameReader, out *frameWriter, cfg OutputStreamSettings) (closed string, dropped int) {
	if out.write(openedFrame{Type: "opened", Protocol: Version, Identity: id, Attempt: s.Attempt(), Seq: s.LastSeq()}) != nil {
		return "", 0
	}
	finish := func(reason string) string {
		if reason == StreamCanceled {
			_ = out.write(bareFrame{Type: "cancel"})
			reason = StreamTerminal
		}
		_ = out.write(closedFrame{Type: "closed", Reason: reason})
		return reason
	}
	if reason := s.Closing(); reason != "" {
		return finish(reason), 0
	}
	ctx, cancel := context.WithCancel(ctx)
	lines := make(chan harnessLine, 16)
	read := make(chan struct{})
	go func() {
		defer close(read)
		readHarness(ctx, in, lines, cfg.IdleTimeout, s.LastSeq())
	}()
	defer func() {
		// The body is not read after the handler returns: end a pending read.
		cancel()
		if in.deadline != nil {
			_ = in.deadline(time.Now())
		}
		<-read
	}()
	var buf []OutputFrame
	size := 0
	acked := s.LastSeq()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var window <-chan time.Time
	// commit stores the buffered frames as one chunk and acknowledges them.
	commit := func() string {
		window = nil
		timer.Stop()
		if len(buf) == 0 {
			return ""
		}
		step, cancel := context.WithTimeout(ctx, 15*time.Second)
		reason, err := s.Append(step, buf)
		cancel()
		buf, size = buf[:0], 0
		if err != nil {
			return StreamUnavailable
		}
		if last := s.LastSeq(); last > acked {
			if out.write(ackFrame{Type: "ack", Seq: last}) != nil {
				return StreamUnavailable
			}
			acked = last
		}
		return reason
	}
	for {
		select {
		case <-ctx.Done():
			return finish(StreamUnavailable), len(buf)
		case sig := <-s.Signals():
			return finish(sig.Reason), len(buf)
		case <-window:
			if reason := commit(); reason != "" {
				return finish(reason), 0
			}
		case l := <-lines:
			switch {
			case l.err != nil:
				reason := StreamInvalid
				if isTimeout(l.err) {
					reason = StreamIdle
				} else if !errors.Is(l.err, ErrProtocol) {
					reason = "" // the harness went away: nobody reads
				}
				if r := commit(); r != "" {
					reason = r
				}
				if reason == "" {
					return "", 0
				}
				return finish(reason), 0
			case l.closing:
				reason := commit()
				if reason == "" {
					reason = StreamDone
				}
				return finish(reason), 0
			}
			// A frame alone over the bound is a chunk alone.
			if l.size >= cfg.CoalesceBytes && len(buf) > 0 {
				if reason := commit(); reason != "" {
					return finish(reason), 1
				}
			}
			buf = append(buf, l.frame)
			size += l.size
			if size >= cfg.CoalesceBytes {
				if reason := commit(); reason != "" {
					return finish(reason), 0
				}
			} else if window == nil {
				timer.Reset(cfg.CoalesceWindow)
				window = timer.C
			}
		}
	}
}

// relayOutputStream is the guest's side: it relays the stream to the host
// frame by frame, the harness's frames up and the platform's down, each
// checked, each flushed, with a deadline per frame. A refusal of the host
// is answered as the host answered it.
func (p *platformHandler) relayOutputStream(ctx context.Context, w http.ResponseWriter, rc *http.ResponseController, local *frameReader, open []byte, host streamOpener) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	body, up := io.Pipe()
	upDone := make(chan error, 1)
	upExited := make(chan struct{})
	go func() {
		defer close(upExited)
		upDone <- pumpHarness(local, up, open)
	}()
	stopUp := func() {
		_ = body.CloseWithError(errStreamClosed)
		if local.deadline != nil {
			_ = local.deadline(time.Now())
		}
	}
	resp, err := host.openStream(ctx, OutputStreamPath, body)
	if err != nil {
		stopUp()
		<-upExited
		code := safePlatformCode(err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(streamRefusalStatus(code))
		_ = json.NewEncoder(w).Encode(platformResponse{Protocol: Version, Identity: p.id, Code: code})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", ndjsonType)
	w.Header().Set("Cache-Control", "no-store")
	out := &frameWriter{w: w, flush: rc.Flush, deadline: rc.SetWriteDeadline, timeout: StreamIdleTimeout + 5*time.Second}
	_ = rc.SetWriteDeadline(time.Now().Add(out.timeout))
	w.WriteHeader(http.StatusOK)
	sequence := controlSequence{identity: p.id}
	closed, upErr := relayPlatform(ctx, cancel, resp.Body, out, &sequence, MaxOutputStreamIdle+5*time.Second, upDone)
	stopUp()
	<-upExited
	switch {
	case closed:
	case errors.Is(upErr, ErrProtocol):
		_ = out.write(closedFrame{Type: "closed", Reason: StreamInvalid})
	default:
		// The host went away, or stopped answering: the harness may open again.
		_ = out.write(closedFrame{Type: "closed", Reason: StreamUnavailable})
	}
}

var errStreamClosed = errors.New("capsule stream closed")

// pumpHarness writes open, then each of the harness's frames, checked, to
// the host, until close; it returns nil after close, the harness's error
// otherwise, and then forwards nothing more: the relay ends the host's call.
// The host keeps its own bound between two frames.
func pumpHarness(local *frameReader, up *io.PipeWriter, open []byte) error {
	if _, err := up.Write(append(open, '\n')); err != nil {
		return err
	}
	for {
		line, err := local.next(MaxOutputStreamIdle + 5*time.Second)
		if err != nil {
			return err
		}
		_, closing, err := parseHarnessFrame(line)
		if err != nil {
			return err
		}
		if _, err = up.Write(append(line, '\n')); err != nil {
			return err
		}
		if closing {
			return up.Close()
		}
	}
}

// relayPlatform copies the host's frames to the local client, each checked
// by sequence and flushed, until closed. It stops early when the harness's
// side fails (upDone), or when the host is silent past idle. closed reports
// that the host's closed frame was relayed; upErr is the harness side's error
// when it stopped the relay (nil when it finished cleanly or not at all).
func relayPlatform(ctx context.Context, cancel context.CancelFunc, from io.Reader, to *frameWriter, sequence *controlSequence, idle time.Duration,
	upDone <-chan error) (closed bool, upErr error) {
	silent := time.AfterFunc(idle, cancel)
	defer silent.Stop()
	type hostLine struct {
		line []byte
		err  error
	}
	lines := make(chan hostLine)
	go func() {
		r := newFrameReader(from, nil)
		for {
			line, err := r.next(idle)
			select {
			case lines <- hostLine{line, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer cancel()
	var failed error // the harness's side failed before opened was relayed
	for {
		select {
		case err := <-upDone:
			upDone = nil // the harness closed: relay the host's answer
			if err != nil && sequence.opened {
				return false, err
			}
			failed = err
		case l := <-lines:
			if l.err != nil {
				return false, nil
			}
			f, err := parseControlFrame(l.line)
			if err != nil || sequence.next(f) != nil {
				return false, nil
			}
			silent.Reset(idle)
			if to.writeLine(append(l.line, '\n')) != nil {
				return false, nil
			}
			if f.Type == "closed" {
				return true, nil
			}
			if failed != nil {
				return false, failed
			}
		case <-ctx.Done():
			return false, nil
		}
	}
}
