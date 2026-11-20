package controlplane

import (
	"context"
	"math/big"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// The operations an alias's model may serve (ADR 023 §12). A platform channel
// route names one: /v1/llm/complete and /v1/llm/forward chat, /v1/llm/embed,
// /v1/llm/transcribe and /v1/llm/ocr their own. vision is informative: the
// gateway does not inspect a forwarded body.
const (
	LLMChat       = "chat"
	LLMVision     = "vision"
	LLMEmbed      = "embed"
	LLMTranscribe = "transcribe"
	LLMOCR        = "ocr"
)

// llmOperations is the canonical order an alias's operations are stored in.
var llmOperations = []string{LLMChat, LLMVision, LLMEmbed, LLMTranscribe, LLMOCR}

// normalizeOperations checks a set of operations and returns it in canonical
// order. An anthropic provider serves chat and vision only: embeddings,
// transcription and OCR go to an openai_compatible provider.
func normalizeOperations(ops []string, providerKind string) ([]string, error) {
	if len(ops) == 0 || len(ops) > len(llmOperations) {
		return nil, ErrInput
	}
	out := []string{}
	for _, op := range llmOperations {
		switch n := countOf(ops, op); {
		case n > 1:
			return nil, ErrInput
		case n == 1:
			if providerKind != "openai_compatible" && op != LLMChat && op != LLMVision {
				return nil, ErrInput
			}
			out = append(out, op)
		}
	}
	if len(out) != len(ops) {
		return nil, ErrInput // an unknown operation
	}
	return out, nil
}

func countOf(s []string, v string) int {
	n := 0
	for _, x := range s {
		if x == v {
			n++
		}
	}
	return n
}

// SetLLMAliasOperationsInput replaces an alias's operations.
type SetLLMAliasOperationsInput struct {
	Operations []string `json:"operations"`
}

// SetLLMAliasOperations replaces the operations an alias serves. It applies
// from the next reservation; a call already reserved goes on.
func (a *Accounts) SetLLMAliasOperations(ctx context.Context, p Principal, alias, key string, in SetLLMAliasOperationsInput) (APIReceipt, error) {
	if !validOrganizationText(alias, 100) || len(in.Operations) == 0 || len(in.Operations) > len(llmOperations) {
		return APIReceipt{}, ErrInput
	}
	canonical, err := normalizeOperations(in.Operations, "openai_compatible")
	if err != nil {
		return APIReceipt{}, err
	}
	tx, err := a.store.begin(ctx)
	if err != nil {
		return APIReceipt{}, err
	}
	defer rollback(tx)
	if _, err = authorizeTenantAdminMutation(ctx, tx, p, authorization.ManageProviders); err != nil {
		return APIReceipt{}, err
	}
	hashed := struct {
		Alias      string
		Operations []string
	}{alias, canonical}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.alias.operations", key, hashed, func() (int, any, error) {
		cur, err := aliasForChange(ctx, tx, p.TenantID, alias)
		if err != nil {
			return 0, nil, err
		}
		var kind string
		if err = tx.QueryRow(ctx, `SELECT kind FROM llm_providers WHERE tenant_id=$1 AND id=$2`, p.TenantID, cur.ProviderID).Scan(&kind); err != nil {
			return 0, nil, err
		}
		ops, err := normalizeOperations(in.Operations, kind)
		if err != nil {
			return 0, nil, err
		}
		if slices.Equal(cur.Operations, ops) {
			return 200, cur, nil
		}
		v, err := scanAlias(tx.QueryRow(ctx, `UPDATE llm_model_aliases SET operations=$3 WHERE tenant_id=$1 AND alias=$2 RETURNING `+aliasColumns, p.TenantID, alias, ops))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, v.ProviderID, &alias, "alias.operations_set"); err != nil {
			return 0, nil, err
		}
		return 200, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}

// llmAmounts is what one call reserves or settles, in its operation's units:
// tokens for chat and embed (an embedding has no output), seconds of audio
// for a transcription, pages for OCR.
type llmAmounts struct {
	Operation           string
	Input, Output       int64
	AudioSeconds, Pages int64
}

// maxLLMUnits bounds a reported amount in any unit, as validUsage does.
const maxLLMUnits = 1e12

// valid says whether the amounts fit their operation. A reservation must
// count something; a settlement may be zero.
func (q llmAmounts) valid(reservation bool) bool {
	for _, v := range []int64{q.Input, q.Output, q.AudioSeconds, q.Pages} {
		if v < 0 || v > maxLLMUnits {
			return false
		}
	}
	switch q.Operation {
	case LLMChat:
		return q.AudioSeconds == 0 && q.Pages == 0 && (!reservation || q.Input+q.Output >= 1)
	case LLMEmbed:
		return q.Output == 0 && q.AudioSeconds == 0 && q.Pages == 0 && (!reservation || q.Input >= 1)
	case LLMTranscribe:
		return q.Input == 0 && q.Output == 0 && q.Pages == 0 && (!reservation || q.AudioSeconds >= 1)
	case LLMOCR:
		return q.Input == 0 && q.Output == 0 && q.AudioSeconds == 0 && q.Pages <= 1e9 && (!reservation || q.Pages >= 1)
	}
	return false
}

// tokens is what a token budget counts of the amounts: transcription and OCR
// count none.
func (q llmAmounts) tokens() int64 { return q.Input + q.Output }

// llmPrices are an alias's prices as a call keeps them from its reservation.
// priced says whether the call's own unit was priced.
type llmPrices struct {
	priced                  bool
	input, output           int64 // per million tokens
	audioPerMinute, perPage int64
}

// cost is the estimated cost of the amounts in micro-units, rounded up once so
// that an estimate never under-reports; ok is false if it does not fit in an
// int64.
func (p llmPrices) cost(q llmAmounts) (int64, bool) {
	switch q.Operation {
	case LLMTranscribe:
		return ceilProduct(q.AudioSeconds, p.audioPerMinute, 60)
	case LLMOCR:
		return ceilProduct(q.Pages, p.perPage, 1)
	}
	return costMicro(q.Input, q.Output, p.input, p.output)
}

// ceilProduct is ceil(a*b/d), exact.
func ceilProduct(a, b, d int64) (int64, bool) {
	v := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	v.Add(v, big.NewInt(d-1))
	v.Quo(v, big.NewInt(d))
	if !v.IsInt64() {
		return 0, false
	}
	return v.Int64(), true
}

// aliasPrices reads the prices an operation's call keeps from its alias.
func aliasPrices(op string, tokensPriced bool, input, output int64, audio, page *int64) llmPrices {
	p := llmPrices{priced: tokensPriced, input: input, output: output}
	if audio != nil {
		p.audioPerMinute = *audio
	}
	if page != nil {
		p.perPage = *page
	}
	switch op {
	case LLMTranscribe:
		p.priced = audio != nil
	case LLMOCR:
		p.priced = page != nil
	}
	return p
}
