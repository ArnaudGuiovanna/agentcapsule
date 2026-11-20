package referenceharness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// The reference harness's output stream (ADR 022): an invocation whose text
// is "/stream <n>" is answered working; the harness then streams n deltas,
// "word1", " word2", …, one every streamPace, between a started and a done
// step, closes the stream, and files the deltas' text as its answer. A
// cancellation stops it: the work is stopped with reason "canceled", and
// "/stream canceled" answers, within the delivery, the invocations whose
// stream the platform canceled. It needs no model: it is the first
// demonstration of streaming, and how a KVM test sees that a cancellation
// reached the harness.

// maxStreamDeltas bounds n: 2,000 deltas at 100 ms take 200 seconds, inside
// the 4 minutes of an invocation's work.
const maxStreamDeltas = 2000

// streamPace is the time between two deltas.
const streamPace = 100 * time.Millisecond

// outputStream is what the harness needs of an output stream: its side of
// capsuleprotocol.OutputStreamWriter.
type outputStream interface {
	Delta(string) error
	Step(step, state, label string) error
	Close(context.Context) (string, error)
	Canceled() <-chan struct{}
	Done() <-chan struct{}
	Abort()
}

// streamOpener is a platform that opens output streams: the platform
// channel's client.
type streamOpener interface {
	OpenOutputStream(context.Context, string) (*capsuleprotocol.OutputStreamWriter, error)
}

// errStreamCanceled: the platform canceled the invocation while it streamed.
var errStreamCanceled = errors.New("the invocation was canceled while it streamed")

// streamCommand reads "/stream <n>" and "/stream canceled".
func streamCommand(in capsuleprotocol.Invocation) (n int, canceled, ok bool) {
	if len(in.Content) != 1 || in.Content[0].Type != "text" || !strings.HasPrefix(in.Content[0].Text, "/stream ") {
		return 0, false, false
	}
	arg := strings.TrimSpace(strings.TrimPrefix(in.Content[0].Text, "/stream "))
	if arg == "canceled" {
		return 0, true, true
	}
	n, err := strconv.Atoi(arg)
	if err != nil || n < 1 || n > maxStreamDeltas {
		return 0, false, true
	}
	return n, false, true
}

// canceledStreams lists the invocations whose stream was canceled, in order.
func canceledStreams(ctx context.Context, tx harnessstore.SQL) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT body FROM reference_outgoing WHERE reason='canceled' ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ops := []string{}
	for rows.Next() {
		var body []byte
		var w work
		if err = rows.Scan(&body); err != nil {
			return nil, err
		}
		if json.Unmarshal(body, &w) == nil && w.Invocation != nil {
			ops = append(ops, w.Invocation.OperationID)
		}
	}
	return ops, rows.Err()
}

// streamText is the text of n deltas, as they are sent.
func streamDeltas(n int) []string {
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("word%d", i+1)
		if i > 0 {
			out[i] = " " + out[i]
		}
	}
	return out
}

// streamOutput sends the deltas on the invocation's output stream. A stream
// that cannot open or that closes early is not an error: the answer is
// filed anyway, since deltas are never the outcome. A cancellation is.
func (h *Engine) streamOutput(ctx context.Context, op string, deltas []string) error {
	open := h.openStream
	if open == nil {
		return nil
	}
	s, err := open(ctx, op)
	var remote *capsuleprotocol.PlatformError
	if errors.As(err, &remote) && remote.Code == "transition" {
		return err // canceled, or ended, before it streamed
	}
	if err != nil {
		return nil
	}
	defer s.Abort()
	canceled := func() bool {
		select {
		case <-s.Canceled():
			return true
		default:
			return false
		}
	}
	_ = s.Step("echo.stream", capsuleprotocol.StepStarted, "Streaming the answer")
	for _, d := range deltas {
		if s.Delta(d) != nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.Canceled():
			return errStreamCanceled
		case <-s.Done():
		case <-time.After(h.streamPace):
		}
		if canceled() {
			return errStreamCanceled
		}
	}
	_ = s.Step("echo.stream", capsuleprotocol.StepDone, "")
	closing, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, _ = s.Close(closing)
	if canceled() {
		return errStreamCanceled
	}
	return nil
}
