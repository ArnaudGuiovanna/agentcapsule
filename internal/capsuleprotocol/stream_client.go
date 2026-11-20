package capsuleprotocol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrStreamClosed: the output stream is closed, by the harness or the
// platform; OutputStreamWriter.Reason says why.
var ErrStreamClosed = errors.New("capsule output stream closed")

// openStream opens a stream route: the request body is streamed as body
// gives it, and the answer is returned once its status and headers have come.
// The HTTP client has no total timeout; ctx bounds the call. A refusal is
// the channel's JSON answer, returned as a *PlatformError.
func (p *PlatformClient) openStream(ctx context.Context, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.client.endpoint(path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ndjsonType)
	client := *p.client.http
	client.Timeout = 0
	r, err := client.Do(req)
	if err != nil {
		return nil, errors.Join(ErrTransport, err)
	}
	if r.StatusCode != http.StatusOK {
		defer r.Body.Close()
		b, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageBytes+1))
		var out platformResponse
		if err != nil || len(b) > MaxMessageBytes || decode(bytes.NewReader(b), &out) != nil || out.Code == "" {
			return nil, ErrProtocol
		}
		if out.Protocol != Version || out.Identity != p.client.identity {
			return nil, ErrIdentity
		}
		return nil, &PlatformError{Code: safePlatformCode(&PlatformError{Code: out.Code})}
	}
	if media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || media != ndjsonType {
		r.Body.Close()
		return nil, ErrProtocol
	}
	return r, nil
}

// OutputStreamWriter is a harness's end of the output stream of a working
// invocation (ADR 022 §5): it sends deltas and steps, and reads the
// platform's acknowledgments, its cancellation and its close. Deltas are
// never the outcome: the harness still files it with CompleteInvocation,
// after Close, so that no frame still buffered is dropped by the outcome.
type OutputStreamWriter struct {
	attempt int
	cancel  context.CancelFunc
	body    *io.PipeWriter

	mu      sync.Mutex
	seq     int64
	closing bool

	acked    atomic.Int64
	canceled chan struct{}
	done     chan struct{}
	// reason and err are set before done closes.
	reason string
	err    error
}

// OpenOutputStream opens the output stream of the working invocation
// operationID. The platform binds it to the invocation's current attempt.
func (p *PlatformClient) OpenOutputStream(ctx context.Context, operationID string) (*OutputStreamWriter, error) {
	return p.openOutputStream(ctx, operationID, nil)
}

// ReopenOutputStream opens the stream again after idle, unavailable or a
// broken connection, naming the attempt its first opening gave. Its frames
// continue after Seq; those not acknowledged must be sent again.
func (p *PlatformClient) ReopenOutputStream(ctx context.Context, operationID string, attempt int) (*OutputStreamWriter, error) {
	if attempt < 1 {
		return nil, ErrProtocol
	}
	return p.openOutputStream(ctx, operationID, &attempt)
}

func (p *PlatformClient) openOutputStream(ctx context.Context, operationID string, attempt *int) (*OutputStreamWriter, error) {
	open, err := encodeFrame(openFrame{Type: "open", Protocol: Version, Identity: p.client.identity, OperationID: operationID, Attempt: attempt})
	if err != nil {
		return nil, err
	}
	if _, err = parseOpen(open[:len(open)-1]); err != nil {
		return nil, err
	}
	// The stream lives as long as the invocation works; ctx bounds only the
	// opening, the connection is the writer's until Close or Abort.
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	body, up := io.Pipe()
	go func() {
		if _, err := up.Write(open); err != nil {
			_ = up.CloseWithError(err)
		}
	}()
	stop := context.AfterFunc(ctx, cancel)
	resp, err := p.openStream(life, OutputStreamPath, body)
	if err != nil {
		stop()
		cancel()
		_ = up.CloseWithError(err)
		return nil, err
	}
	r := newFrameReader(resp.Body, nil)
	sequence := controlSequence{identity: p.client.identity}
	line, err := r.next(0)
	stop()
	var first ControlFrame
	if err == nil {
		first, err = parseControlFrame(line)
	}
	if err == nil {
		err = sequence.next(first)
	}
	if err != nil {
		cancel()
		resp.Body.Close()
		_ = up.CloseWithError(err)
		if ctx.Err() != nil {
			return nil, errors.Join(ErrTransport, ctx.Err())
		}
		return nil, ErrProtocol
	}
	w := &OutputStreamWriter{attempt: first.Attempt, cancel: cancel, body: up, seq: first.Seq,
		canceled: make(chan struct{}), done: make(chan struct{})}
	w.acked.Store(first.Seq)
	go w.read(r, resp.Body, &sequence)
	return w, nil
}

// read follows the platform's frames until closed, the end of the
// connection, or a silence longer than any stream may keep.
func (w *OutputStreamWriter) read(r *frameReader, body io.Closer, sequence *controlSequence) {
	silent := time.AfterFunc(MaxOutputStreamIdle+10*time.Second, w.cancel)
	defer func() {
		silent.Stop()
		body.Close()
		w.cancel()
		_ = w.body.CloseWithError(ErrStreamClosed)
		close(w.done)
	}()
	for {
		line, err := r.next(0)
		if err != nil {
			w.err = errors.Join(ErrTransport, err)
			return
		}
		f, err := parseControlFrame(line)
		if err == nil {
			err = sequence.next(f)
		}
		if err != nil {
			w.err = ErrProtocol
			return
		}
		silent.Reset(MaxOutputStreamIdle + 10*time.Second)
		switch f.Type {
		case "ack":
			w.acked.Store(f.Seq)
		case "cancel":
			close(w.canceled)
		case "closed":
			w.reason = f.Reason
			return
		}
	}
}

// Attempt is the invocation's attempt the stream is bound to.
func (w *OutputStreamWriter) Attempt() int { return w.attempt }

// Seq is the seq of the last frame sent.
func (w *OutputStreamWriter) Seq() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seq
}

// Acked is the last seq the platform stored: every frame up to it is stored.
func (w *OutputStreamWriter) Acked() int64 { return w.acked.Load() }

// Canceled is closed when the platform says the invocation was canceled:
// the harness may stop its work. The stream then closes.
func (w *OutputStreamWriter) Canceled() <-chan struct{} { return w.canceled }

// Done is closed when the stream has closed.
func (w *OutputStreamWriter) Done() <-chan struct{} { return w.done }

// Reason is the platform's closed reason once Done is closed, "" when the
// connection ended without one (see Err).
func (w *OutputStreamWriter) Reason() string {
	select {
	case <-w.done:
		return w.reason
	default:
		return ""
	}
}

// Err is why the stream ended without a closed frame, once Done is closed.
func (w *OutputStreamWriter) Err() error {
	select {
	case <-w.done:
		return w.err
	default:
		return nil
	}
}

// Delta sends a fragment of text: non-empty UTF-8, without NUL.
func (w *OutputStreamWriter) Delta(text string) error {
	return w.send(OutputFrame{Type: "delta", Text: text})
}

// Step sends a step: its name (^[a-z][a-z0-9_.-]{0,63}$), its state
// (StepStarted, StepDone, StepFailed) and an optional label.
func (w *OutputStreamWriter) Step(step, state, label string) error {
	return w.send(OutputFrame{Type: "step", Step: step, State: state, Label: label})
}

func (w *OutputStreamWriter) send(f OutputFrame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closing {
		return ErrStreamClosed
	}
	select {
	case <-w.done:
		return ErrStreamClosed
	default:
	}
	f.Seq = w.seq + 1
	b, err := f.Encode()
	if err != nil {
		return err
	}
	if len(b)+1 > MaxStreamFrameBytes {
		return ErrProtocol
	}
	if _, err = w.body.Write(append(b, '\n')); err != nil {
		return ErrStreamClosed
	}
	w.seq = f.Seq
	return nil
}

// Close sends close and waits for the platform's closed frame, within ctx;
// it returns its reason: StreamDone once every frame sent is stored. Another
// reason says why some were not.
func (w *OutputStreamWriter) Close(ctx context.Context) (string, error) {
	w.mu.Lock()
	if !w.closing {
		w.closing = true
		select {
		case <-w.done:
		default:
			if _, err := w.body.Write([]byte(`{"type":"close"}` + "\n")); err == nil {
				_ = w.body.Close()
			}
		}
	}
	w.mu.Unlock()
	select {
	case <-w.done:
		if w.reason == "" {
			return "", w.err
		}
		return w.reason, nil
	case <-ctx.Done():
		w.Abort()
		return "", ctx.Err()
	}
}

// Abort drops the connection at once; frames not acknowledged may be lost.
func (w *OutputStreamWriter) Abort() {
	w.cancel()
	_ = w.body.CloseWithError(ErrStreamClosed)
}
