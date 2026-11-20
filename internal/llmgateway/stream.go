package llmgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// Event is one provider event: its SSE event name (Anthropic) and its data,
// a JSON object, exactly as the provider sent them. Data is at most 60 KiB
// and Name a token of at most 64 bytes, so that one event fits in a channel
// frame of 64 KiB when written without escaping.
type Event struct {
	Name string          // "" for OpenAI, the `event:` field for Anthropic
	Data json.RawMessage // the `data:` field, a JSON object
}

// StreamResult is a finished stream's usage. FinishReason is set by
// CompleteStream only. FirstEvent is the time from the provider request to
// its first event; it is set once an event has come, even when the stream is
// then cut.
type StreamResult struct {
	Usage        Usage
	FinishReason string
	FirstEvent   time.Duration
}

// MaxStreamText bounds one text fragment CompleteStream gives its sink. A
// longer fragment of the provider is split between two characters, so that a
// fragment's frame on the channel fits in 64 KiB even with every character
// escaped.
const MaxStreamText = 8 << 10

// A stream cut after the provider's first byte: its outcome is unknown. The
// causes say why, for tests and the span; none holds content.
var (
	errStreamCut      = errors.New("llm stream cut after the first byte")
	errStreamEnded    = errors.New("llm stream ended before its final event")
	errStreamUsage    = errors.New("llm stream ended without its final usage")
	errStreamEvent    = errors.New("llm stream event is not a JSON object")
	errStreamProvider = errors.New("llm stream carried a provider error")
	errStreamSize     = errors.New("llm stream exceeded its size bound")
	errStreamType     = errors.New("llm stream answer is not an event stream")
	errStreamIdle     = errors.New("llm stream idle too long")
	errStreamTotal    = errors.New("llm stream exceeded its total bound")
	errFirstByte      = errors.New("llm stream first byte too late")
	errSink           = errors.New("llm stream sink failed")
)

// streamCut is the error of a stream cut after its first byte:
// ErrOutcomeUnknown, errStreamCut and the cause.
func streamCut(cause error) error {
	return fmt.Errorf("%w: %w: %w", ErrOutcomeUnknown, errStreamCut, cause)
}

// ForwardStreamOutputCap is ForwardOutputCap for a stream request: the body
// must hold "stream": true.
func ForwardStreamOutputCap(dialect string, body []byte) (int, error) {
	_, max, err := forwardFields(dialect, body, true)
	return max, err
}

// ForwardStream sends an agent's native stream request (its body holds
// "stream": true) to its alias's provider and calls sink once per provider
// event, in order, exactly as the provider sent it; OpenAI's final [DONE]
// and a provider's error event are not relayed. It returns once the stream
// has ended with its usage.
//
// Before the provider's first byte, retries and refusals are Forward's. After
// it nothing is retried: a cut, a timeout, a stream past its bounds or
// without its final usage, or a sink error (which cancels the provider call)
// is ErrOutcomeUnknown. The breaker records a success only at the end.
func (g *Gateway) ForwardStream(ctx context.Context, route Route, dialect string, body []byte, sink func(Event) error) (out StreamResult, err error) {
	ctx, span := startStream(ctx, "forward", route)
	defer func() { endCall(span, out.Usage, err) }()
	if !route.validAuth() || route.UpstreamModel == "" || sink == nil {
		return StreamResult{}, ErrInvalid
	}
	fields, _, err := forwardFields(dialect, body, true)
	if err != nil {
		return StreamResult{}, err
	}
	var target string
	switch {
	case dialect == DialectOpenAI && route.Kind == "openai_compatible":
		target = join(route.BaseURL, "/chat/completions")
	case dialect == DialectAnthropic && route.Kind == "anthropic":
		target = join(route.BaseURL, "/v1/messages")
	default:
		return StreamResult{}, ErrDialect
	}
	model, err := json.Marshal(route.UpstreamModel)
	if err != nil {
		return StreamResult{}, ErrInvalid
	}
	fields["model"] = model
	streamFields(fields, dialect)
	prepared, err := json.Marshal(fields)
	if err != nil || len(prepared) > MaxForwardBytes+len(model)+64 {
		return StreamResult{}, ErrInvalid
	}
	state := streamState{dialect: dialect}
	out.FirstEvent, err = g.stream(ctx, route.Key, target, prepared, route.headers(), func(e Event) (bool, error) {
		relay, err := state.read(e)
		if err != nil || !relay {
			return state.done, err
		}
		if err = sink(e); err != nil {
			return false, fmt.Errorf("%w: %w", errSink, err)
		}
		return state.done, nil
	})
	if err != nil {
		return out, err
	}
	out.Usage = state.usage()
	return out, nil
}

// CompleteStream is Complete as a stream: it calls sink with each fragment of
// the answer's text (OpenAI's choices[0].delta.content, Anthropic's
// text_delta), never empty and at most MaxStreamText bytes, and returns the
// usage and the finish reason. Retries, outcomes and the breaker are
// ForwardStream's.
func (g *Gateway) CompleteStream(ctx context.Context, route Route, req Request, sink func(text string) error) (out StreamResult, err error) {
	ctx, span := startStream(ctx, "complete", route)
	defer func() { endCall(span, out.Usage, err) }()
	if !req.valid() || !route.validAuth() || route.UpstreamModel == "" || sink == nil {
		return StreamResult{}, ErrInvalid
	}
	var build func(Route, Request) (string, []byte, map[string]string, error)
	var dialect string
	switch route.Kind {
	case "openai_compatible":
		build, dialect = buildOpenAI, DialectOpenAI
	case "anthropic":
		build, dialect = buildAnthropic, DialectAnthropic
	default:
		return StreamResult{}, ErrInvalid
	}
	target, body, headers, err := build(route, req)
	if err != nil {
		return StreamResult{}, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(body, &fields); err != nil {
		return StreamResult{}, ErrInvalid
	}
	streamFields(fields, dialect)
	if body, err = json.Marshal(fields); err != nil {
		return StreamResult{}, ErrInvalid
	}
	state := streamState{dialect: dialect}
	out.FirstEvent, err = g.stream(ctx, route.Key, target, body, headers, func(e Event) (bool, error) {
		if _, err := state.read(e); err != nil {
			return false, err
		}
		for text := state.text; text != ""; {
			n := len(text)
			if n > MaxStreamText {
				n = MaxStreamText
				for n > 0 && !utf8.RuneStart(text[n]) {
					n--
				}
				if n == 0 {
					n = MaxStreamText // not UTF-8: json.Unmarshal never gives such a string
				}
			}
			if err := sink(text[:n]); err != nil {
				return false, fmt.Errorf("%w: %w", errSink, err)
			}
			text = text[n:]
		}
		return state.done, nil
	})
	if err != nil {
		return out, err
	}
	out.Usage, out.FinishReason = state.usage(), state.finish
	return out, nil
}

// streamFields asks for a stream, and for OpenAI its final usage, replacing
// the agent's own stream_options.
func streamFields(fields map[string]json.RawMessage, dialect string) {
	fields["stream"] = json.RawMessage("true")
	delete(fields, "stream_options")
	if dialect == DialectOpenAI {
		fields["stream_options"] = json.RawMessage(`{"include_usage":true}`)
	}
}

func startStream(ctx context.Context, entry string, route Route) (context.Context, *telemetry.Span) {
	ctx, span := startCall(ctx, entry, route)
	span.Code("agentcapsule.llm.mode", "stream")
	return ctx, span
}

// stream is one logical streaming call. Up to the provider's first byte it
// retries as exchange does; after it, never. read receives each event and
// says when the stream has ended. It returns the time to the first event.
func (g *Gateway) stream(ctx context.Context, breakerKey, target string, body []byte, headers map[string]string, read func(Event) (bool, error)) (time.Duration, error) {
	if g.cfg.RequireHTTPS && !strings.HasPrefix(target, "https://") {
		return 0, ErrRejected // the configuration is wrong; nothing is sent
	}
	if err := g.admit(breakerKey); err != nil {
		return 0, err
	}
	caller := ctx
	ctx, cancel := context.WithTimeoutCause(ctx, g.cfg.StreamTotal, errStreamTotal)
	defer cancel()
	var last error
	for attempt := 0; attempt < g.cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			if err := g.cfg.Sleep(ctx, g.cfg.Backoff<<(attempt-1)); err != nil {
				g.record(breakerKey, true) // release a half-open probe; not a provider fault
				return 0, err
			}
		}
		telemetry.SpanFrom(ctx).Int("agentcapsule.llm.attempts", int64(attempt+1))
		start := time.Now()
		resp, stop, retry, err := g.open(ctx, target, body, headers)
		if err == nil {
			first, err := g.follow(resp, stop, start, read)
			switch {
			case err == nil:
				g.record(breakerKey, true)
			case errors.Is(err, errSink) || caller.Err() != nil:
				g.release(breakerKey) // the caller left: neither a success nor a fault
			default:
				g.record(breakerKey, false)
			}
			return first, err
		}
		if errors.Is(err, ErrRejected) {
			g.record(breakerKey, true) // the provider is healthy; the request was wrong
			return 0, err
		}
		last = err
		if !retry {
			break
		}
	}
	g.record(breakerKey, false)
	return 0, last
}

// open sends one attempt and waits for the provider's first byte: its status
// and headers, within StreamFirstByte. It returns a 2xx event stream and the
// function that cancels its reading, or whether the error may be retried.
func (g *Gateway) open(ctx context.Context, target string, body []byte, headers map[string]string) (*http.Response, context.CancelCauseFunc, bool, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		cancel(nil)
		return nil, nil, false, ErrInvalid
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "text/event-stream")
	for k, v := range headers {
		hr.Header.Set(k, v)
	}
	late := time.AfterFunc(g.cfg.StreamFirstByte, func() { cancel(errFirstByte) })
	resp, err := g.http.Do(hr)
	if !late.Stop() && err == nil {
		// The bound passed as the answer came: too late all the same.
		resp.Body.Close()
		err = context.Cause(ctx)
	}
	if err != nil {
		cancel(nil)
		if errors.Is(err, ErrAddressRefused) {
			return nil, nil, false, ErrAddressRefused // nothing was sent
		}
		if ctx.Err() != nil || isTimeout(err) {
			// Sent, answer never seen: do not retry, do not claim zero cost.
			return nil, nil, false, ErrOutcomeUnknown
		}
		return nil, nil, true, ErrUnavailable // could not connect; nothing was accepted
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		cancel(nil)
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			return nil, nil, true, ErrRateLimited
		case resp.StatusCode >= 500:
			return nil, nil, true, ErrUnavailable
		}
		// A redirect is never followed: see once.
		return nil, nil, false, fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
	if media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || media != "text/event-stream" {
		// A 2xx: the provider may have done the work, in another form.
		resp.Body.Close()
		cancel(nil)
		return nil, nil, false, streamCut(errStreamType)
	}
	return resp, cancel, false, nil
}

// follow reads an event stream after its first byte, within the idle and
// size bounds, until read says it has ended.
func (g *Gateway) follow(resp *http.Response, stop context.CancelCauseFunc, start time.Time, read func(Event) (bool, error)) (first time.Duration, err error) {
	defer stop(nil)
	defer resp.Body.Close()
	idle := time.AfterFunc(g.cfg.StreamIdle, func() { stop(errStreamIdle) })
	defer idle.Stop()
	alive := func() { idle.Reset(g.cfg.StreamIdle) }
	events := newSSEReader(&boundedReader{r: resp.Body, left: g.cfg.MaxResponse}, alive)
	ctx := resp.Request.Context()
	for {
		name, data, err := events.next()
		if err != nil {
			if cause := context.Cause(ctx); cause != nil {
				err = cause // the read failed because the stream was canceled
			} else if errors.Is(err, io.EOF) {
				err = errStreamEnded
			}
			return first, streamCut(err)
		}
		alive()
		if first == 0 {
			first = max(time.Since(start), time.Nanosecond)
		}
		done, err := read(Event{Name: name, Data: data})
		if err != nil {
			return first, streamCut(err)
		}
		if done {
			return first, nil
		}
	}
}

// release ends a half-open probe without a verdict.
func (g *Gateway) release(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if b := g.breakers[key]; b != nil {
		b.probing = false
	}
}

// boundedReader fails once more than left bytes have been read.
type boundedReader struct {
	r    io.Reader
	left int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errStreamSize
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.r.Read(p)
	if b.left -= int64(n); b.left < 0 {
		return 0, errStreamSize
	}
	return n, err
}

// streamState follows one stream's events in its dialect: it checks each,
// keeps the usage, the finish reason and the current text fragment, and says
// when the stream has ended.
type streamState struct {
	dialect string
	done    bool
	finish  string
	text    string // the text of the last event read, for CompleteStream
	// OpenAI: the last usage chunk.
	input, output *int64
	// Anthropic: message_start's usage, each field replaced by those a
	// message_delta carries.
	in, cacheCreate, cacheRead, out *int64
	started, delta                  bool
}

type openAIChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		Prompt     *int64 `json:"prompt_tokens"`
		Completion *int64 `json:"completion_tokens"`
	} `json:"usage"`
	Error json.RawMessage `json:"error"`
}

type anthropicUsage struct {
	In          *int64 `json:"input_tokens"`
	CacheCreate *int64 `json:"cache_creation_input_tokens"`
	CacheRead   *int64 `json:"cache_read_input_tokens"`
	Out         *int64 `json:"output_tokens"`
}

type anthropicEvent struct {
	Type    string `json:"type"`
	Message *struct {
		Usage *anthropicUsage `json:"usage"`
	} `json:"message"`
	Delta *struct {
		Type       string  `json:"type"`
		Text       string  `json:"text"`
		StopReason *string `json:"stop_reason"`
	} `json:"delta"`
	Usage *anthropicUsage `json:"usage"`
}

// read checks one event and says whether to relay it.
func (s *streamState) read(e Event) (bool, error) {
	s.text = ""
	if s.dialect == DialectOpenAI && bytes.Equal(bytes.TrimSpace(e.Data), []byte("[DONE]")) {
		if s.input == nil || s.output == nil {
			return false, errStreamUsage
		}
		s.done = true
		return false, nil
	}
	if !utf8.Valid(e.Data) || !bytes.HasPrefix(bytes.TrimLeft(e.Data, " \t\n\r"), []byte("{")) {
		return false, errStreamEvent
	}
	if s.dialect == DialectOpenAI {
		var v openAIChunk
		if json.Unmarshal(e.Data, &v) != nil {
			return false, errStreamEvent
		}
		if len(v.Error) > 0 && !bytes.Equal(v.Error, []byte("null")) {
			return false, errStreamProvider
		}
		if v.Usage != nil && v.Usage.Prompt != nil && v.Usage.Completion != nil {
			if !validCount(v.Usage.Prompt) || !validCount(v.Usage.Completion) {
				return false, errStreamUsage
			}
			s.input, s.output = v.Usage.Prompt, v.Usage.Completion
		}
		if len(v.Choices) > 0 {
			s.text = v.Choices[0].Delta.Content
			if r := v.Choices[0].FinishReason; r != nil {
				s.finish = *r
			}
		}
		return true, nil
	}
	var v anthropicEvent
	if json.Unmarshal(e.Data, &v) != nil {
		return false, errStreamEvent
	}
	switch v.Type {
	case "error":
		return false, errStreamProvider
	case "message_start":
		if v.Message == nil || v.Message.Usage == nil || v.Message.Usage.In == nil {
			return false, errStreamUsage
		}
		s.started = true
		if !s.take(v.Message.Usage) {
			return false, errStreamUsage
		}
	case "message_delta":
		if v.Usage != nil {
			if v.Usage.Out == nil || !s.take(v.Usage) {
				return false, errStreamUsage
			}
			s.delta = true
		}
		if v.Delta != nil && v.Delta.StopReason != nil {
			s.finish = *v.Delta.StopReason
		}
	case "content_block_delta":
		if v.Delta != nil && v.Delta.Type == "text_delta" {
			s.text = v.Delta.Text
		}
	case "message_stop":
		// The end, relayed only with its usage: else the client would take
		// the answer for a whole one.
		if !s.started || !s.delta {
			return false, errStreamUsage
		}
		s.done = true
	}
	return true, nil
}

// take replaces the usage fields u carries.
func (s *streamState) take(u *anthropicUsage) bool {
	for _, f := range []struct{ to, from **int64 }{{&s.in, &u.In}, {&s.cacheCreate, &u.CacheCreate}, {&s.cacheRead, &u.CacheRead}, {&s.out, &u.Out}} {
		if *f.from != nil {
			if !validCount(*f.from) {
				return false
			}
			*f.to = *f.from
		}
	}
	return true
}

// validCount is a token count a provider may report: at most 10^12, as the
// accounting accepts.
func validCount(n *int64) bool { return n != nil && *n >= 0 && *n <= 1e12 }

func (s *streamState) usage() Usage {
	v := func(n *int64) int64 {
		if n == nil {
			return 0
		}
		return *n
	}
	if s.dialect == DialectOpenAI {
		return Usage{v(s.input), v(s.output)}
	}
	return Usage{v(s.in) + v(s.cacheCreate) + v(s.cacheRead), v(s.out)}
}
