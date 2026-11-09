package controlplane

import (
	"context"
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// ErrLLMAlreadyProcessed: this request key already has a reservation that is not
// safe to replay. The caller must use a new key to ask again.
var ErrLLMAlreadyProcessed = errors.New("llm request key already used")

// LLMService is the metered path an agent's model call takes: resolve the
// alias, reserve budget, call the provider, then settle, mark unknown or
// release. It holds no prompt or completion after returning them.
type LLMService struct {
	accounts *Accounts
	gateway  *llmgateway.Gateway
}

func NewLLMService(a *Accounts, g *llmgateway.Gateway) (*LLMService, error) {
	if a == nil || g == nil {
		return nil, ErrInput
	}
	return &LLMService{accounts: a, gateway: g}, nil
}

type LLMResult struct {
	llmgateway.Response
	SoftBudgetExceeded bool
}

// estimateTokens is a deliberately pessimistic upper bound used only to reserve
// budget: about one token per three bytes of input, plus the output cap.
func estimateTokens(q llmgateway.Request) int64 {
	var bytes int64
	for _, m := range q.Messages {
		bytes += int64(len(m.Content))
	}
	out := int64(q.MaxTokens)
	if out == 0 {
		out = 1024
	}
	return bytes/3 + 1 + out
}

// Call is keyed by requestKey, unique per agent. tenantID and agentID must come
// from the authenticated channel, never from the request body.
func (s *LLMService) Call(ctx context.Context, tenantID, agentID, alias, requestKey string, q llmgateway.Request) (LLMResult, error) {
	h, err := s.admit(ctx, tenantID, agentID, alias, requestKey, estimateTokens(q))
	if err != nil {
		return LLMResult{}, err
	}
	return s.execute(ctx, h, q)
}

// llmHold is an admitted call: a resolved route and a live reservation.
type llmHold struct {
	tenantID, alias string
	route           LLMRoute
	res             LLMReservation
}

// admit resolves the alias and reserves budget. Nothing has reached the provider.
func (s *LLMService) admit(ctx context.Context, tenantID, agentID, alias, requestKey string, estimate int64) (llmHold, error) {
	route, err := s.accounts.ResolveLLMRoute(ctx, tenantID, alias)
	if err != nil {
		return llmHold{}, err
	}
	res, err := s.accounts.ReserveLLM(ctx, tenantID, agentID, alias, requestKey, estimate)
	if err != nil {
		return llmHold{}, err
	}
	if res.Replayed {
		// A reservation still "reserved" means an earlier attempt may have sent
		// the call before dying: count it as uncertain, never as free.
		if res.State == "reserved" {
			_ = s.accounts.MarkLLMUnknown(ctx, tenantID, res.ID)
			return llmHold{}, llmgateway.ErrOutcomeUnknown
		}
		return llmHold{}, ErrLLMAlreadyProcessed
	}
	return llmHold{tenantID: tenantID, alias: alias, route: route, res: res}, nil
}

// execute calls the provider and settles, marks unknown or releases.
func (s *LLMService) execute(ctx context.Context, h llmHold, q llmgateway.Request) (LLMResult, error) {
	var out llmgateway.Response
	err := s.settle(ctx, h, func(route llmgateway.Route) (usage llmgateway.Usage, err error) {
		out, err = s.gateway.Complete(ctx, route, q)
		return out.Usage, err
	})
	if err != nil {
		return LLMResult{}, err
	}
	return LLMResult{Response: out, SoftBudgetExceeded: h.res.SoftExceeded}, nil
}

// settle runs one provider call for an admitted hold and records its single
// outcome: settled at the reported usage, unknown, or released.
func (s *LLMService) settle(ctx context.Context, h llmHold, call func(llmgateway.Route) (llmgateway.Usage, error)) error {
	route := h.route
	usage, callErr := call(llmgateway.Route{Kind: route.Kind, BaseURL: route.BaseURL, UpstreamModel: route.UpstreamModel, Secret: route.Secret, Key: h.tenantID + "/" + h.alias})
	// Bookkeeping must survive a cancelled caller context.
	bk := context.WithoutCancel(ctx)
	switch {
	case callErr == nil:
		return s.accounts.SettleLLM(bk, h.tenantID, h.res.ID, usage.InputTokens, usage.OutputTokens)
	case errors.Is(callErr, llmgateway.ErrOutcomeUnknown):
		_ = s.accounts.MarkLLMUnknown(bk, h.tenantID, h.res.ID)
	default:
		// Refused, rate limited, unreachable or invalid: the provider did no
		// billable work, so the reservation is given back.
		_ = s.accounts.ReleaseLLM(bk, h.tenantID, h.res.ID)
	}
	return callErr
}

// CallFromVM serves a model call made by a running capsule. Identity, tenant and
// placement come from the authenticated VM channel; the guest only names an
// alias. admission runs the placement check and the reservation in one guarded
// section (the worker's host admission), then the slow provider call runs
// OUTSIDE it so a model call never holds up a wake, sleep or delete.
func (s *LLMService) CallFromVM(ctx context.Context, caller VMCaller, requestKey, alias string, q llmgateway.Request,
	admission func(context.Context, func(context.Context) error) error) (LLMResult, error) {
	hold, err := s.admitFromVM(ctx, caller, requestKey, alias, estimateTokens(q), admission)
	if err != nil {
		return LLMResult{}, err
	}
	return s.execute(ctx, hold, q)
}

// admitFromVM runs the placement check and the reservation in one guarded section.
func (s *LLMService) admitFromVM(ctx context.Context, caller VMCaller, requestKey, alias string, estimate int64,
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
		hold, err = s.admit(ctx, tenant, caller.AgentID, alias, requestKey, estimate)
		return err
	}
	var err error
	if admission == nil {
		err = step(ctx)
	} else {
		err = admission(ctx, step)
	}
	return hold, err
}

// ForwardResult is a provider's answer to an agent's native request.
type ForwardResult struct {
	llmgateway.ForwardResponse
	SoftBudgetExceeded bool
}

// forwardDefaultOutput is reserved when a forwarded request declares no output
// cap. Settlement records what the provider reports, so a longer answer is
// still counted; a hard budget then refuses the next call.
const forwardDefaultOutput = 4096

// ForwardFromVM serves an agent's native model request (the model endpoint
// inside the VM): the same placement check, reservation and single outcome as
// CallFromVM. The guest names the alias as its model; tenant and agent come from
// the authenticated channel.
func (s *LLMService) ForwardFromVM(ctx context.Context, caller VMCaller, requestKey, alias, dialect string, body []byte,
	admission func(context.Context, func(context.Context) error) error) (ForwardResult, error) {
	max, err := llmgateway.ForwardOutputCap(dialect, body)
	if err != nil {
		return ForwardResult{}, err
	}
	if max == 0 {
		max = forwardDefaultOutput
	}
	hold, err := s.admitFromVM(ctx, caller, requestKey, alias, int64(len(body))/3+1+int64(max), admission)
	if err != nil {
		return ForwardResult{}, err
	}
	var out llmgateway.ForwardResponse
	err = s.settle(ctx, hold, func(route llmgateway.Route) (usage llmgateway.Usage, err error) {
		out, err = s.gateway.Forward(ctx, route, dialect, body)
		return out.Usage, err
	})
	if err != nil {
		return ForwardResult{}, err
	}
	return ForwardResult{ForwardResponse: out, SoftBudgetExceeded: hold.res.SoftExceeded}, nil
}
