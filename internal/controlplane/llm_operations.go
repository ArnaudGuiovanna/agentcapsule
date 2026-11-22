package controlplane

import (
	"context"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/accounting"
)

// The operations an alias's model may serve (ADR 023 §12). A platform channel
// route names one: /v1/llm/complete and /v1/llm/forward chat, /v1/llm/embed,
// /v1/llm/transcribe and /v1/llm/ocr their own. vision is informative: the
// gateway does not inspect a forwarded body.
const (
	LLMChat       = accounting.Chat
	LLMVision     = accounting.Vision
	LLMEmbed      = accounting.Embed
	LLMTranscribe = accounting.Transcribe
	LLMOCR        = accounting.OCR
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

// LLMAmounts holds a reservation or settlement in the units of its operation.
type LLMAmounts = accounting.Amounts
