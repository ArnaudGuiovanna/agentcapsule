//go:build linux

package worker

import (
	"cmp"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The output streams of working invocations (ADR 022 §5): a harness sends
// its deltas and steps over one long call on its platform channel; the
// worker coalesces them into sealed chunks in PostgreSQL, acknowledges them,
// and tells the harness when the invocation is canceled or has its outcome.

// ServiceOutputStreams is the output_streams section of the worker's
// configuration. Every key is optional and takes its default.
type ServiceOutputStreams struct {
	CoalesceWindow string `json:"coalesce_window,omitempty"`
	CoalesceBytes  int    `json:"coalesce_bytes,omitempty"`
	MaxBytes       int64  `json:"max_bytes,omitempty"`
	MaxFrames      int    `json:"max_frames,omitempty"`
	Retention      string `json:"retention,omitempty"`
	IdleTimeout    string `json:"idle_timeout,omitempty"`
}

// OutputStreams are the worker's bounds of the output streams.
type OutputStreams struct {
	Settings capsuleprotocol.OutputStreamSettings
	Limits   controlplane.StreamLimits
}

// DefaultOutputStreams: 150 ms or 4 KiB of coalescing, 2 MiB and 4,096
// frames per attempt, chunks kept 10 minutes after the outcome, 60 seconds
// between two frames.
var DefaultOutputStreams = OutputStreams{Settings: capsuleprotocol.DefaultOutputStreamSettings, Limits: controlplane.DefaultStreamLimits}

// ErrOutputStreams refuses an output_streams value out of its bounds.
var ErrOutputStreams = errors.New("invalid output_streams configuration")

// OutputStreamBounds reads the output_streams section; the defaults without
// it.
func (c ServiceConfig) OutputStreamBounds() (OutputStreams, error) {
	o := DefaultOutputStreams
	s := c.OutputStreams
	if s == nil {
		return o, nil
	}
	o.Settings.CoalesceBytes = cmp.Or(s.CoalesceBytes, o.Settings.CoalesceBytes)
	o.Limits.MaxBytes = cmp.Or(s.MaxBytes, o.Limits.MaxBytes)
	o.Limits.MaxFrames = cmp.Or(s.MaxFrames, o.Limits.MaxFrames)
	for _, d := range []struct {
		text string
		out  *time.Duration
	}{{s.CoalesceWindow, &o.Settings.CoalesceWindow}, {s.Retention, &o.Limits.Retention}, {s.IdleTimeout, &o.Settings.IdleTimeout}} {
		if d.text == "" {
			continue
		}
		v, err := time.ParseDuration(d.text)
		if err != nil {
			return o, ErrOutputStreams
		}
		*d.out = v
	}
	if !o.Settings.Valid() || !o.Limits.Valid() {
		return o, ErrOutputStreams
	}
	return o, nil
}

// outputStreams is what the platform channels need to serve the streams.
type outputStreams struct {
	OutputStreams
	// hub wakes a stream on its invocation's notifications; nil polls
	// every second.
	hub pgnotify.Hub
}

// EnableOutputStreams serves the output streams of the host's VMs, once.
// hub is the worker's notification hub (pgnotify), nil to poll.
func (w *Placements) EnableOutputStreams(o OutputStreams, hub pgnotify.Hub) error {
	if !o.Settings.Valid() || !o.Limits.Valid() {
		return ErrOutputStreams
	}
	if !w.streams.CompareAndSwap(nil, &outputStreams{OutputStreams: o, hub: hub}) {
		return controlplane.ErrConflict
	}
	return nil
}

// streamRetention is how long chunks are kept after their outcome.
func (w *Placements) streamRetention() time.Duration {
	if o := w.streams.Load(); o != nil {
		return o.Limits.Retention
	}
	return controlplane.DefaultStreamLimits.Retention
}

// The streams' metrics (ADR 022 §5.12).
var (
	streamKinds    = []string{"output", "llm"}
	streamOutcomes = []string{"stored", "refused", "truncated"}
)

// streamTelemetry counts the streams of the host's platform channels. The
// model streams (kind llm) use it too.
type streamTelemetry struct {
	open       *telemetry.Gauge
	frames     *telemetry.Counter
	firstDelta *telemetry.Histogram
	mu         sync.Mutex
	opened     map[string]int
}

// EnableStreamTelemetry registers the streams' metrics, every series served
// from zero. Call it once per registry.
func (w *Placements) EnableStreamTelemetry(registry *telemetry.Registry) error {
	if registry == nil {
		return controlplane.ErrInput
	}
	t := &streamTelemetry{
		open: registry.Gauge("agentcapsule_worker_streams_open", "Streams open on the platform channels of the host's VMs: output streams of working invocations, and model streams.",
			telemetry.Label{Name: "kind", Values: streamKinds}),
		frames: registry.Counter("agentcapsule_worker_stream_frames_total", "Frames of output streams: stored in a chunk, refused (invalid, after the outcome, of an old attempt or boot, or dropped at the close), or past the attempt's limits.",
			telemetry.Label{Name: "outcome", Values: streamOutcomes}),
		firstDelta: registry.Histogram("agentcapsule_worker_stream_first_delta_seconds", "From an invocation's working answer to the first stored delta of its attempt.",
			[]float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}),
		opened: map[string]int{},
	}
	for _, k := range streamKinds {
		t.open.Set(0, k)
	}
	for _, o := range streamOutcomes {
		t.frames.Add(0, o)
	}
	if !w.streamTelemetry.CompareAndSwap(nil, t) {
		return controlplane.ErrConflict
	}
	return nil
}

// track counts one more open stream of kind and returns its end.
func (t *streamTelemetry) track(kind string) func() {
	if t == nil {
		return func() {}
	}
	t.mu.Lock()
	t.opened[kind]++
	t.open.Set(float64(t.opened[kind]), kind)
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			t.opened[kind]--
			t.open.Set(float64(t.opened[kind]), kind)
			t.mu.Unlock()
		})
	}
}

func (t *streamTelemetry) count(outcome string, n int) {
	if t != nil && n > 0 {
		t.frames.Add(float64(n), outcome)
	}
}

// OutputStreamSettings are the host's bounds of the streams it serves.
func (a platformAPI) OutputStreamSettings() capsuleprotocol.OutputStreamSettings {
	if a.output != nil {
		if o := a.output(); o != nil {
			return o.Settings
		}
	}
	return capsuleprotocol.DefaultOutputStreamSettings
}

// OpenOutputStream opens the output stream of a working invocation of the
// calling boot (ADR 022 §5.4), under the host's admission like every guest
// effect; the stream then runs outside it, each chunk checked again in its
// own transaction. The span platform.call lasts the stream's life, and its
// outcome is the stream's closed reason.
func (a platformAPI) OpenOutputStream(ctx context.Context, op string, attempt int) (capsuleprotocol.OutputStream, error) {
	traced, end := a.trace(ctx, "output_stream", "invocation", op)
	var o *outputStreams
	if a.output != nil {
		o = a.output()
	}
	var transit *controlplane.Transit
	if a.transit != nil {
		transit = a.transit()
	}
	if o == nil || transit == nil {
		end(controlplane.ErrUnavailable)
		return nil, platformError(controlplane.ErrUnavailable)
	}
	var opened controlplane.StreamOpening
	err := a.withApplication(traced, func(ctx context.Context) error {
		var err error
		opened, err = transit.OpenOutputStreamFromVM(ctx, a.caller, op, attempt)
		return err
	})
	if err != nil {
		end(err)
		return nil, platformError(err)
	}
	var metrics *streamTelemetry
	if a.streamTelemetry != nil {
		metrics = a.streamTelemetry()
	}
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s := &outputStream{api: a, transit: transit, limits: o.Limits, op: op, opened: opened, last: opened.LastSeq,
		signals: make(chan capsuleprotocol.StreamSignal, 1), stop: cancel, watched: make(chan struct{}),
		span: telemetry.SpanFrom(traced), metrics: metrics, untrack: metrics.track("output")}
	go s.watch(life, o.hub)
	return s, nil
}

// outputStream is one open output stream on the host.
type outputStream struct {
	api     platformAPI
	transit *controlplane.Transit
	limits  controlplane.StreamLimits
	op      string
	opened  controlplane.StreamOpening
	last    int64
	signals chan capsuleprotocol.StreamSignal
	stop    context.CancelFunc
	watched chan struct{}
	span    *telemetry.Span
	metrics *streamTelemetry
	untrack func()
}

func (s *outputStream) Attempt() int    { return s.opened.Attempt }
func (s *outputStream) LastSeq() int64  { return s.last }
func (s *outputStream) Closing() string { return s.opened.Closing }

// Append commits one chunk in its own transaction, outside the host's
// admission: the transaction checks the boot, the working state, the due
// time and the attempt again.
func (s *outputStream) Append(ctx context.Context, frames []capsuleprotocol.OutputFrame) (string, error) {
	r, err := s.transit.AppendOutputStreamFromVM(ctx, s.api.caller, s.op, s.opened.Attempt, frames, s.limits)
	if err != nil {
		s.metrics.count("refused", len(frames))
		return "", err
	}
	if r.Stored > 0 {
		s.last = r.LastSeq
	}
	s.metrics.count("stored", r.Stored)
	if r.Reason == capsuleprotocol.StreamTruncated {
		s.metrics.count("truncated", len(frames)-r.Stored)
	} else {
		s.metrics.count("refused", len(frames)-r.Stored)
	}
	if r.FirstDelta > 0 && s.metrics != nil {
		s.metrics.firstDelta.Observe(r.FirstDelta.Seconds())
	}
	return r.Reason, nil
}

func (s *outputStream) Signals() <-chan capsuleprotocol.StreamSignal { return s.signals }

// watch reads the invocation's state at each notification of its
// operation, and every second without a hub, until a reason to close.
func (s *outputStream) watch(ctx context.Context, hub pgnotify.Hub) {
	defer close(s.watched)
	var wake <-chan struct{}
	if hub != nil {
		c, unsubscribe := hub.Subscribe("agentcapsule_invocation_stream", s.op)
		defer unsubscribe()
		wake = c
	} else {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		ticks := make(chan struct{}, 1)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					select {
					case ticks <- struct{}{}:
					default:
					}
				}
			}
		}()
		wake = ticks
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}
		read, cancel := context.WithTimeout(ctx, 5*time.Second)
		reason, err := s.api.store.OutputStreamSignal(read, s.api.caller, s.op, s.opened.Attempt)
		cancel()
		if err == nil && reason != "" {
			s.signals <- capsuleprotocol.StreamSignal{Reason: reason}
			return
		}
	}
}

// Close ends the stream: its watch, its count, and its span with the closed
// reason as outcome.
func (s *outputStream) Close(reason string, dropped int) {
	s.stop()
	<-s.watched
	s.metrics.count("refused", dropped)
	s.untrack()
	if s.span != nil {
		outcome := reason
		if outcome == "" {
			outcome = "unavailable"
		}
		s.span.Code("agentcapsule.outcome", outcome)
		switch reason {
		case capsuleprotocol.StreamDone, capsuleprotocol.StreamTerminal, capsuleprotocol.StreamReset, capsuleprotocol.StreamExpired, capsuleprotocol.StreamTruncated:
		default:
			s.span.Fail()
		}
		s.span.End()
	}
}

var _ capsuleprotocol.OutputStreamAPI = platformAPI{}
var _ capsuleprotocol.OutputStreamTuning = platformAPI{}
