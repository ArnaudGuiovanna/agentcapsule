package controlplane

import (
	"context"
	"errors"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmpolicy"
	"github.com/jackc/pgx/v5"
)

// SetLLMAliasRequestPolicyInput replaces an alias's request policy
// (llmpolicy.RequestPolicy, v0.1.0 audit findings S-11 and S-13): the
// top-level fields and the tool types a forwarded request may use beside the
// plain ones, and the output cap of a call that declares none. A list left
// out is empty, MaxOutputTokens left out is the platform's default, and
// OutputCapField left out is max_tokens.
type SetLLMAliasRequestPolicyInput struct {
	AllowedFields    []string `json:"allowed_fields"`
	AllowedToolTypes []string `json:"allowed_tool_types"`
	MaxOutputTokens  *int64   `json:"max_output_tokens,omitempty"`
	OutputCapField   string   `json:"output_cap_field,omitempty"`
}

// normalizeRequestPolicy checks a policy and returns it with sorted lists
// and its default cap field. A name repeated, of another syntax, or one the
// gateway rules on itself (model, messages, stream, n, the output caps) is
// refused. An anthropic provider reads max_tokens only; kind "" skips that
// check, for a provider not yet read.
func normalizeRequestPolicy(in SetLLMAliasRequestPolicyInput, kind string) (SetLLMAliasRequestPolicyInput, error) {
	out := SetLLMAliasRequestPolicyInput{MaxOutputTokens: in.MaxOutputTokens, OutputCapField: in.OutputCapField}
	for _, list := range []struct {
		from []string
		to   *[]string
	}{{in.AllowedFields, &out.AllowedFields}, {in.AllowedToolTypes, &out.AllowedToolTypes}} {
		if len(list.from) > llmpolicy.MaxPolicyNames {
			return SetLLMAliasRequestPolicyInput{}, ErrInput
		}
		names := slices.Clone(list.from)
		slices.Sort(names)
		for i, name := range names {
			if !llmpolicy.ValidPolicyName(name) || (i > 0 && names[i-1] == name) || (list.to == &out.AllowedFields && llmpolicy.GatewayField(name)) {
				return SetLLMAliasRequestPolicyInput{}, ErrInput
			}
		}
		*list.to = append([]string{}, names...)
	}
	if out.MaxOutputTokens != nil && (*out.MaxOutputTokens < 1 || *out.MaxOutputTokens > 1_000_000) {
		return SetLLMAliasRequestPolicyInput{}, ErrInput
	}
	switch out.OutputCapField {
	case "":
		out.OutputCapField = "max_tokens"
	case "max_tokens":
	case "max_completion_tokens":
		if kind == "anthropic" {
			return SetLLMAliasRequestPolicyInput{}, ErrInput
		}
	default:
		return SetLLMAliasRequestPolicyInput{}, ErrInput
	}
	return out, nil
}

// llmAliasAccess refuses with reason alias_access an agent that may not call
// a listed alias, as the reservation does; nil when it may.
func (a *Accounts) llmAliasAccess(ctx context.Context, tenantID, agentID, alias string) error {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var access string
	if err = tx.QueryRow(ctx, `SELECT access FROM llm_model_aliases WHERE tenant_id=$1 AND alias=$2 AND status='active'`, tenantID, alias).Scan(&access); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if access == "listed" {
		granted, err := aliasGranted(ctx, tx, tenantID, alias, agentID)
		if err != nil {
			return err
		}
		if !granted {
			return &LLMRefusal{Reason: "alias_access"}
		}
	}
	return commit(ctx, tx)
}

func samePolicy(a LLMAlias, p SetLLMAliasRequestPolicyInput) bool {
	return slices.Equal(a.AllowedFields, p.AllowedFields) && slices.Equal(a.AllowedToolTypes, p.AllowedToolTypes) &&
		samePrice(a.MaxOutputTokens, p.MaxOutputTokens) && a.OutputCapField == p.OutputCapField
}

// SetLLMAliasRequestPolicy replaces what an alias lets a call ask of its
// provider. It applies from the next reservation; a call already reserved
// goes on with the policy it was admitted under.
func (a *Accounts) SetLLMAliasRequestPolicy(ctx context.Context, p Principal, alias, key string, in SetLLMAliasRequestPolicyInput) (APIReceipt, error) {
	if !validOrganizationText(alias, 100) {
		return APIReceipt{}, ErrInput
	}
	policy, err := normalizeRequestPolicy(in, "")
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
		Alias  string
		Policy SetLLMAliasRequestPolicyInput
	}{alias, policy}
	r, err := a.withTenantReceipt(ctx, tx, p, "llm.alias.request_policy", key, hashed, func() (int, any, error) {
		cur, err := aliasForChange(ctx, tx, p.TenantID, alias)
		if err != nil {
			return 0, nil, err
		}
		var kind string
		if err = tx.QueryRow(ctx, `SELECT kind FROM llm_providers WHERE tenant_id=$1 AND id=$2`, p.TenantID, cur.ProviderID).Scan(&kind); err != nil {
			return 0, nil, err
		}
		if _, err = normalizeRequestPolicy(policy, kind); err != nil {
			return 0, nil, err
		}
		if samePolicy(cur, policy) {
			return 200, cur, nil
		}
		v, err := scanAlias(tx.QueryRow(ctx, `UPDATE llm_model_aliases SET allowed_fields=$3,allowed_tool_types=$4,max_output_tokens=$5,output_cap_field=$6
            WHERE tenant_id=$1 AND alias=$2 RETURNING `+aliasColumns, p.TenantID, alias, policy.AllowedFields, policy.AllowedToolTypes, policy.MaxOutputTokens, policy.OutputCapField))
		if err != nil {
			return 0, nil, err
		}
		if err = auditLLM(ctx, tx, p, v.ProviderID, &alias, "alias.request_policy_set"); err != nil {
			return 0, nil, err
		}
		return 200, v, nil
	})
	if err != nil {
		return APIReceipt{}, err
	}
	return r, commit(ctx, tx)
}
