package controlplane

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// ErrLLMAlreadyProcessed: this request key already has a reservation that is not
// safe to replay. The caller must use a new key to ask again.
var ErrLLMAlreadyProcessed = errors.New("llm request key already used")

// ErrLLMConcurrency refuses, before any reservation, a model call of an agent
// that already has as many calls in flight in this process as its limit
// (LimitCallsPerAgent). The agent may call again when one ends.
var ErrLLMConcurrency = errors.New("too many model calls of this agent in flight")

// DefaultLLMCallsPerAgent is how many model calls an agent may have in flight
// at once, every route counted (chat, streams, embeddings, transcription,
// OCR), unless the worker's configuration says otherwise.
const DefaultLLMCallsPerAgent = 8

// LLMService is the metered path an agent's model call takes: resolve the
// alias, reserve budget, call the provider, then settle, mark unknown or
// release. It holds no prompt or completion after returning them.
type LLMService struct {
	accounts *Accounts
	gateway  *llmgateway.Gateway
	observer atomic.Pointer[observerBox]
	inflight inflightKeys
	perAgent atomic.Int64
}

// LimitCallsPerAgent sets how many model calls an agent may have in flight at
// once in this process; n < 1 restores DefaultLLMCallsPerAgent. An agent's
// calls all come through the platform channel of its one running VM, hence
// through one worker.
func (s *LLMService) LimitCallsPerAgent(n int) {
	if n < 1 {
		n = 0
	}
	s.perAgent.Store(int64(n))
}

func (s *LLMService) callsPerAgent() int {
	if n := s.perAgent.Load(); n > 0 {
		return int(n)
	}
	return DefaultLLMCallsPerAgent
}

type observerBox struct{ LLMObserver }

// LLMCallEvent is what the operator learns of one metered call: closed codes
// and counts, never an organization, agent, alias, model, key or content.
type LLMCallEvent struct {
	// Provider is the provider's kind (openai_compatible, anthropic); empty
	// when the alias did not resolve.
	Provider string
	// Outcome is settled, released, unknown or refused.
	Outcome string
	// Reason, Period and Scope describe a refusal (see LLMRefusal).
	Reason, Period, Scope string
	// Settled usage and its estimated cost (micro-units; 0 when unpriced).
	InputTokens, OutputTokens, CostMicro int64
	// Operation is embed, transcribe or ocr for those routes, empty for chat;
	// AudioSeconds and Pages are their settled units (ADR 023 §12).
	Operation           string
	AudioSeconds, Pages int64
	// SoftBudgets are the soft budgets this call went past.
	SoftBudgets []LLMBudgetHit
}

// LLMObserver receives one event per call that reached a reservation or was
// refused by policy. It must not block.
type LLMObserver interface{ ObserveLLM(LLMCallEvent) }

func NewLLMService(a *Accounts, g *llmgateway.Gateway) (*LLMService, error) {
	if a == nil || g == nil {
		return nil, ErrInput
	}
	return &LLMService{accounts: a, gateway: g}, nil
}

// Observe sets the operator's observer (metrics and logs).
func (s *LLMService) Observe(o LLMObserver) {
	if o == nil {
		s.observer.Store(nil)
		return
	}
	s.observer.Store(&observerBox{o})
}

func (s *LLMService) observe(e LLMCallEvent) {
	if o := s.observer.Load(); o != nil {
		o.ObserveLLM(e)
	}
}

type LLMResult struct {
	llmgateway.Response
	SoftBudgetExceeded bool
}

// messageOverhead is what a text call's estimate adds per message, for its
// role and separators.
const messageOverhead = 4

// textCall plans a text call on its alias: its messages' estimated tokens
// (llmgateway.EstimateTokens) and the output cap the provider is held to
// (llmgateway.CompleteOutputCap, which the gateway writes into the request).
func textCall(q llmgateway.Request) llmPlan {
	return func(route LLMRoute) (llmAmounts, error) {
		var input int64
		for _, m := range q.Messages {
			input += llmgateway.EstimateTokens([]byte(m.Content)) + messageOverhead
		}
		return llmAmounts{Operation: LLMChat, Input: input, Output: int64(llmgateway.CompleteOutputCap(route.Policy, q))}, nil
	}
}

// forwardCall plans a forwarded request on its alias: the alias's request
// policy, the body's estimate with its media by reference, and the output cap
// the provider is held to (llmgateway.PlanForward).
func forwardCall(dialect string, body []byte, stream bool) llmPlan {
	return func(route LLMRoute) (llmAmounts, error) {
		plan, err := llmgateway.PlanForward(route.Policy, dialect, body, stream)
		return llmAmounts{Operation: LLMChat, Input: plan.Input, Output: plan.Output}, err
	}
}

// Call is keyed by requestKey, unique per agent. tenantID and agentID must come
// from the authenticated channel, never from the request body.
func (s *LLMService) Call(ctx context.Context, tenantID, agentID, alias, requestKey string, q llmgateway.Request) (LLMResult, error) {
	h, err := s.admit(ctx, tenantID, agentID, alias, requestKey, textCall(q))
	if err != nil {
		return LLMResult{}, err
	}
	return s.execute(ctx, h, q)
}

// llmHold is an admitted call: a resolved route, a live reservation and the
// amounts it reserved. done releases its request key and its agent's slot
// once its outcome is recorded (settle).
type llmHold struct {
	tenantID, alias string
	route           LLMRoute
	res             LLMReservation
	reserved        llmAmounts
	done            func()
}

// llmPlan says what a call reserves once its alias's route is known. It
// refuses, before any reservation, what the alias's request policy does not
// allow.
type llmPlan func(LLMRoute) (llmAmounts, error)

// admit claims the call's request key and a slot of its agent, resolves the
// alias, plans the call on it and reserves budget. Nothing has reached the
// provider. A refusal by policy (calls in flight, request policy, alias
// access, operation, hard budget) is observed. Every route of a call, chat or
// not, comes through here (audit finding L-07). The claim comes first, so
// that a call beyond its agent's limit costs no database work.
func (s *LLMService) admit(ctx context.Context, tenantID, agentID, alias, requestKey string, plan llmPlan) (llmHold, error) {
	key, agent := inflightKey(tenantID, agentID, requestKey), inflightAgent(tenantID, agentID)
	switch s.inflight.claim(key, agent, s.callsPerAgent()) {
	case keyRunning:
		// A call with this key runs in this process: it may have reached the
		// provider, and records its own outcome.
		return llmHold{}, llmgateway.ErrOutcomeUnknown
	case agentFull:
		s.observe(LLMCallEvent{Outcome: "refused", Reason: "concurrency_limited"})
		return llmHold{}, ErrLLMConcurrency
	}
	done := func() { s.inflight.release(key, agent) }
	// A disabled organization's agents call no model (organization_suspension.go):
	// its VM, still running until the worker puts it to sleep, is refused
	// before any route or reservation, with the guest's code for a call it
	// may not make (unauthorized).
	if disabled, err := organizationDisabled(ctx, s.accounts.store.pool, tenantID); err != nil || disabled {
		done()
		if err == nil {
			err = errors.Join(ErrForbidden, ErrOrganizationDisabled)
		}
		return llmHold{}, err
	}
	route, q, err := s.plan(ctx, tenantID, agentID, alias, plan)
	if err != nil {
		done()
		return llmHold{}, err
	}
	res, err := s.accounts.reserveLLM(ctx, tenantID, agentID, alias, requestKey, q, &route)
	if errors.Is(err, errLLMRouteChanged) {
		// The credential was rotated since the route was resolved: the new
		// one serves the call.
		if route, q, err = s.plan(ctx, tenantID, agentID, alias, plan); err == nil {
			res, err = s.accounts.reserveLLM(ctx, tenantID, agentID, alias, requestKey, q, &route)
		}
	}
	var refused *LLMRefusal
	if errors.As(err, &refused) {
		s.observe(LLMCallEvent{Provider: route.Kind, Operation: operationLabel(q.Operation), Outcome: "refused", Reason: refused.Reason, Period: refused.Period, Scope: refused.Scope})
	}
	if err != nil {
		done()
		return llmHold{}, err
	}
	if res.Replayed {
		done()
		// A reservation still "reserved" that no call of this process holds
		// means an earlier attempt may have sent the call before dying: count
		// it as uncertain, never as free.
		if res.State == "reserved" {
			_ = s.accounts.MarkLLMUnknown(ctx, tenantID, res.ID)
			return llmHold{}, llmgateway.ErrOutcomeUnknown
		}
		return llmHold{}, ErrLLMAlreadyProcessed
	}
	return llmHold{tenantID: tenantID, alias: alias, route: route, res: res, reserved: q, done: done}, nil
}

// plan resolves the alias and plans the call on its route. A request its
// alias's policy refuses is observed as feature_denied, unless the agent may
// not call the alias at all: the refusal is then alias_access, as the
// reservation would have said, so that an agent learns nothing of an alias
// not granted to it.
func (s *LLMService) plan(ctx context.Context, tenantID, agentID, alias string, plan llmPlan) (LLMRoute, llmAmounts, error) {
	route, err := s.accounts.ResolveLLMRoute(ctx, tenantID, alias)
	if err != nil {
		return LLMRoute{}, llmAmounts{}, err
	}
	q, err := plan(route)
	if errors.Is(err, llmgateway.ErrFeatureDenied) {
		var refused *LLMRefusal
		if access := s.accounts.llmAliasAccess(ctx, tenantID, agentID, alias); errors.As(access, &refused) {
			s.observe(LLMCallEvent{Provider: route.Kind, Outcome: "refused", Reason: refused.Reason})
			return LLMRoute{}, llmAmounts{}, access
		} else if access != nil {
			return LLMRoute{}, llmAmounts{}, access
		}
		s.observe(LLMCallEvent{Provider: route.Kind, Outcome: "refused", Reason: "feature_denied"})
	}
	return route, q, err
}

// operationLabel is an event's operation: empty for chat.
func operationLabel(op string) string {
	if op == LLMChat {
		return ""
	}
	return op
}

// execute calls the provider and settles, marks unknown or releases.
func (s *LLMService) execute(ctx context.Context, h llmHold, q llmgateway.Request) (LLMResult, error) {
	var out llmgateway.Response
	settled, err := s.settle(ctx, h, func(route llmgateway.Route) (llmgateway.Usage, llmgateway.Unreported, error) {
		var err error
		out, err = s.gateway.Complete(ctx, route, q)
		return out.Usage, out.Unreported, err
	})
	if err != nil {
		return LLMResult{}, err
	}
	out.Usage, out.Unreported = settled, llmgateway.Unreported{}
	return LLMResult{Response: out, SoftBudgetExceeded: h.res.SoftExceeded}, nil
}

// gatewayRoute is the gateway's view of a hold's route.
func (h llmHold) gatewayRoute() llmgateway.Route {
	r := h.route
	return llmgateway.Route{AuthMode: r.AuthMode, Kind: r.Kind, BaseURL: r.BaseURL, UpstreamModel: r.UpstreamModel, Secret: r.Secret,
		Key: h.tenantID + "/" + h.alias, Policy: r.Policy}
}

// settle runs one provider call for an admitted hold and records its single
// outcome: settled at the reported usage, unknown, or released. A count the
// provider's answer left out is settled at the reservation's (audit finding
// L-06): the input estimate, the output cap. It returns the settled usage.
func (s *LLMService) settle(ctx context.Context, h llmHold, call func(llmgateway.Route) (llmgateway.Usage, llmgateway.Unreported, error)) (llmgateway.Usage, error) {
	defer h.release()
	usage, missing, callErr := call(h.gatewayRoute())
	if missing.Input {
		usage.InputTokens = h.reserved.Input
	}
	if missing.Output {
		usage.OutputTokens = h.reserved.Output
	}
	// Bookkeeping must survive a cancelled caller context.
	bk := context.WithoutCancel(ctx)
	event := LLMCallEvent{Provider: h.route.Kind, SoftBudgets: h.res.SoftBudgets}
	switch {
	case callErr == nil:
		cost, err := s.accounts.settleLLM(bk, h.tenantID, h.res.ID, usage.InputTokens, usage.OutputTokens)
		if err != nil {
			return llmgateway.Usage{}, err
		}
		event.Outcome, event.InputTokens, event.OutputTokens = "settled", usage.InputTokens, usage.OutputTokens
		if cost != nil {
			event.CostMicro = *cost
		}
	case errors.Is(callErr, llmgateway.ErrOutcomeUnknown):
		_ = s.accounts.MarkLLMUnknown(bk, h.tenantID, h.res.ID)
		event.Outcome = "unknown"
	default:
		// Refused, rate limited, unreachable or invalid: the provider did no
		// billable work, so the reservation is given back.
		_ = s.accounts.ReleaseLLM(bk, h.tenantID, h.res.ID)
		event.Outcome = "released"
	}
	s.observe(event)
	return usage, callErr
}

// CallFromVM serves a model call made by a running capsule. Identity, tenant and
// placement come from the authenticated VM channel; the guest only names an
// alias. admission runs the placement check and the reservation in one guarded
// section (the worker's host admission), then the slow provider call runs
// OUTSIDE it so a model call never holds up a wake, sleep or delete.
func (s *LLMService) CallFromVM(ctx context.Context, caller VMCaller, requestKey, alias string, q llmgateway.Request,
	admission func(context.Context, func(context.Context) error) error) (LLMResult, error) {
	hold, err := s.admitFromVM(ctx, caller, requestKey, alias, textCall(q), admission)
	if err != nil {
		return LLMResult{}, err
	}
	return s.execute(ctx, hold, q)
}

// admitFromVM runs the placement check and the reservation in one guarded
// section, for every route of the platform channel. A call reserved under an
// admission that then fails never runs: its reservation is released, since
// nothing reached the provider, and its key given back (audit finding L-08).
func (s *LLMService) admitFromVM(ctx context.Context, caller VMCaller, requestKey, alias string, plan llmPlan,
	admission func(context.Context, func(context.Context) error) error) (llmHold, error) {
	if requireIdentity(caller.AgentID, requestKey) != nil || len(requestKey) > 200 {
		return llmHold{}, ErrInput
	}
	var hold llmHold
	step := func(ctx context.Context) error {
		tenant, err := s.accounts.store.vmTenant(ctx, caller)
		if err != nil {
			return err
		}
		hold, err = s.admit(ctx, tenant, caller.AgentID, alias, requestKey, plan)
		return err
	}
	var err error
	if admission == nil {
		err = step(ctx)
	} else {
		err = admission(ctx, step)
	}
	if err != nil && hold.res.ID != "" {
		_ = s.accounts.ReleaseLLM(context.WithoutCancel(ctx), hold.tenantID, hold.res.ID)
		hold.release()
		return llmHold{}, err
	}
	return hold, err
}

// ForwardResult is a provider's answer to an agent's native request.
type ForwardResult struct {
	llmgateway.ForwardResponse
	SoftBudgetExceeded bool
}

// ForwardFromVM serves an agent's native model request (the model endpoint
// inside the VM): the same placement check, reservation and single outcome as
// CallFromVM. The guest names the alias as its model; tenant and agent come from
// the authenticated channel. The alias's request policy applies before any
// reservation, and a request without an output cap is held to the alias's
// (llmgateway.PlanForward).
func (s *LLMService) ForwardFromVM(ctx context.Context, caller VMCaller, requestKey, alias, dialect string, body []byte,
	admission func(context.Context, func(context.Context) error) error) (ForwardResult, error) {
	if _, err := llmgateway.ForwardOutputCap(dialect, body); err != nil {
		return ForwardResult{}, err
	}
	hold, err := s.admitFromVM(ctx, caller, requestKey, alias, forwardCall(dialect, body, false), admission)
	if err != nil {
		return ForwardResult{}, err
	}
	var out llmgateway.ForwardResponse
	settled, err := s.settle(ctx, hold, func(route llmgateway.Route) (llmgateway.Usage, llmgateway.Unreported, error) {
		var err error
		out, err = s.gateway.Forward(ctx, route, dialect, body)
		return out.Usage, out.Unreported, err
	})
	if err != nil {
		return ForwardResult{}, err
	}
	out.Usage, out.Unreported = settled, llmgateway.Unreported{}
	return ForwardResult{ForwardResponse: out, SoftBudgetExceeded: hold.res.SoftExceeded}, nil
}

// Probe is for the local worker operator diagnostic. The upstream is resolved
// from a registered alias and the request uses the production egress policy.
func (s *LLMService) Probe(ctx context.Context, tenant, alias string) (llmgateway.ProbeResult, error) {
	route, err := s.accounts.ResolveLLMRoute(ctx, tenant, alias)
	if err != nil {
		return llmgateway.ProbeResult{}, err
	}
	return s.gateway.Probe(ctx, llmgateway.Route{Kind: route.Kind, BaseURL: route.BaseURL, AuthMode: route.AuthMode, UpstreamModel: route.UpstreamModel, Secret: route.Secret})
}
