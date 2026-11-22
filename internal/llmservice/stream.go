package llmservice

import (
	"context"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// How a model stream ended (ADR 022 §4.2, the `end` frame's outcome).
const (
	StreamCompleted      = "completed"
	StreamOutcomeUnknown = "outcome_unknown"
)

// StreamEnd ends a model stream whose first event was relayed, or that
// completed. With StreamCompleted it carries the usage settled, the soft
// budget warning and, for CompleteStreamFromVM, the finish reason. With
// StreamOutcomeUnknown it carries nothing: the provider may have billed
// the call, its reservation stays counted as unknown, and the key must not be
// sent again.
type StreamEnd struct {
	Outcome            string
	Usage              llmgateway.Usage
	FinishReason       string
	SoftBudgetExceeded bool
}

// StreamObserver is an Observer that also times model streams. It must
// not block.
type StreamObserver interface {
	Observer
	// ObserveFirstEvent receives, for each stream whose provider sent an
	// event, the time from the provider request to its first event.
	ObserveFirstEvent(time.Duration)
}

// ForwardStreamFromVM serves an agent's native model request as a stream
// (ADR 022 §3): its body holds "stream": true. It is admitted as
// ForwardFromVM is (placement, alias access, the alias's request policy,
// budgets, reservation from llmgateway.PlanForward, request key, the agent's
// calls in flight), then sink receives each
// provider event, in order, as the provider sent it, then the call is settled
// once.
//
// An error means sink was never called: the call was refused or failed before
// its first event, with ForwardFromVM's errors (llmgateway.ErrOutcomeUnknown
// included: a replay of a key not settled, or a stream cut before its first
// event). Once sink has been called the error is nil and the end's Outcome
// says how the stream ended. A sink error cancels the provider call: the
// outcome is unknown.
func (s *Service) ForwardStreamFromVM(ctx context.Context, caller controlplane.VMCaller, requestKey, alias, dialect string, body []byte,
	admission func(context.Context, func(context.Context) error) error, sink func(llmgateway.Event) error) (StreamEnd, error) {
	if _, err := llmgateway.ForwardStreamOutputCap(dialect, body); err != nil {
		return StreamEnd{}, err
	}
	hold, err := s.admitFromVM(ctx, caller, requestKey, alias, forwardCall(dialect, body, true), admission)
	if err != nil {
		return StreamEnd{}, err
	}
	relayed := false
	out, err := s.settleStream(ctx, hold, func(route llmgateway.Route) (llmgateway.StreamResult, error) {
		return s.gateway.ForwardStream(ctx, route, dialect, body, func(e llmgateway.Event) error {
			relayed = true
			return sink(e)
		})
	})
	return hold.streamEnd(out, relayed, err)
}

// CompleteStreamFromVM is CallFromVM as a stream: sink receives each fragment
// of the answer's text (never empty, at most llmgateway.MaxStreamText
// bytes). Admission, errors and the end are ForwardStreamFromVM's.
func (s *Service) CompleteStreamFromVM(ctx context.Context, caller controlplane.VMCaller, requestKey, alias string, q llmgateway.Request,
	admission func(context.Context, func(context.Context) error) error, sink func(text string) error) (StreamEnd, error) {
	hold, err := s.admitFromVM(ctx, caller, requestKey, alias, textCall(q), admission)
	if err != nil {
		return StreamEnd{}, err
	}
	relayed := false
	out, err := s.settleStream(ctx, hold, func(route llmgateway.Route) (llmgateway.StreamResult, error) {
		return s.gateway.CompleteStream(ctx, route, q, func(text string) error {
			relayed = true
			return sink(text)
		})
	})
	return hold.streamEnd(out, relayed, err)
}

// settleStream runs one stream for an admitted hold and records its single
// outcome as settle does: settled at the usage of its final events, unknown
// after a cut, or released after a refusal before the first byte.
func (s *Service) settleStream(ctx context.Context, h llmHold, call func(llmgateway.Route) (llmgateway.StreamResult, error)) (llmgateway.StreamResult, error) {
	var out llmgateway.StreamResult
	// A stream without its final usage is a cut (ErrOutcomeUnknown): its
	// usage is always reported.
	_, err := s.settle(ctx, h, func(route llmgateway.Route) (llmgateway.Usage, llmgateway.Unreported, error) {
		var err error
		out, err = call(route)
		return out.Usage, llmgateway.Unreported{}, err
	})
	if o := s.observer.Load(); o != nil && out.FirstEvent > 0 {
		if timed, ok := o.Observer.(StreamObserver); ok {
			timed.ObserveFirstEvent(out.FirstEvent)
		}
	}
	return out, err
}

// streamEnd is the end of an admitted stream. After its first relayed event,
// every failure, a settlement's included, is an unknown outcome.
func (h llmHold) streamEnd(out llmgateway.StreamResult, relayed bool, err error) (StreamEnd, error) {
	switch {
	case err == nil:
		return StreamEnd{Outcome: StreamCompleted, Usage: out.Usage, FinishReason: out.FinishReason, SoftBudgetExceeded: h.res.SoftExceeded}, nil
	case relayed:
		return StreamEnd{Outcome: StreamOutcomeUnknown}, nil
	}
	return StreamEnd{}, err
}
