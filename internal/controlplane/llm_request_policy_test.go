package controlplane

import (
	"encoding/json"
	"testing"
)

// policyStoreLab holds the aliases of the LLM service's request policy tests
// (internal/llmservice/request_policy_test.go): "fast" (openai_compatible,
// chat), "embed" (the same provider, embeddings) and "claude" (anthropic).
type policyStoreLab struct {
	*tenantLab
	owner Principal
}

func newPolicyStoreLab(t *testing.T) *policyStoreLab {
	t.Helper()
	l, _, owner := agentLab(t)
	providers := map[string]string{}
	for _, v := range []struct{ key, kind string }{{"pp-openai", "openai_compatible"}, {"pp-anthropic", "anthropic"}} {
		r, err := l.a.CreateLLMProvider(t.Context(), owner, v.key, CreateLLMProviderInput{Name: v.key, Kind: v.kind, BaseURL: "https://llm.example.org", Secret: providerSecret})
		var made LLMProvider
		if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &made) != nil {
			t.Fatal("create provider", err)
		}
		providers[v.kind] = made.ID
	}
	for _, a := range []CreateLLMAliasInput{
		{Alias: "fast", ProviderID: providers["openai_compatible"]},
		{Alias: "embed", ProviderID: providers["openai_compatible"], Operations: []string{"embed"}},
		{Alias: "claude", ProviderID: providers["anthropic"]},
	} {
		a.UpstreamModel, a.InputMicroPerMTok, a.OutputMicroPerMTok = "up-"+a.Alias, price(1_000_000), price(1_000_000)
		if _, err := l.a.CreateLLMAlias(t.Context(), owner, "alias-"+a.Alias, a); err != nil {
			t.Fatal(a.Alias, err)
		}
	}
	return &policyStoreLab{tenantLab: l, owner: owner}
}

// Migration 68 on an installation that already has aliases and audit rows:
// every alias allows nothing beyond the plain fields and keeps the default
// output cap, and the audit takes the new action. The schema refuses what the
// API refuses.
func TestLLMRequestPolicyMigrationKeepsExistingAliases(t *testing.T) {
	p := newPolicyStoreLab(t)
	if _, err := p.s.pool.Exec(t.Context(), `
        ALTER TABLE llm_audit DROP CONSTRAINT llm_audit_action_check,
          ADD CONSTRAINT llm_audit_action_check CHECK (action IN ('provider.created','provider.rotated','provider.disabled','alias.created','alias.disabled',
            'budget.created','budget.disabled','alias.access_set','alias.prices_set','alias.grant_created','alias.grant_revoked','usage.settled','usage.released',
            'alias.operations_set'));
        ALTER TABLE llm_model_aliases DROP COLUMN allowed_fields, DROP COLUMN allowed_tool_types, DROP COLUMN max_output_tokens, DROP COLUMN output_cap_field`); err != nil {
		t.Fatal("revert", err)
	}
	if _, err := p.s.pool.Exec(t.Context(), migrationSQL(t, "llm-request-policy")); err != nil {
		t.Fatal("migrate", err)
	}
	items, err := p.a.ListLLMAliases(t.Context(), p.owner, "", 10)
	if err != nil || len(items) != 3 {
		t.Fatal(items, err)
	}
	for _, a := range items {
		if a.AllowedFields == nil || len(a.AllowedFields) != 0 || len(a.AllowedToolTypes) != 0 || a.MaxOutputTokens != nil || a.OutputCapField != "max_tokens" {
			t.Fatal("alias after migration", a)
		}
	}
	if r, err := p.a.SetLLMAliasRequestPolicy(t.Context(), p.owner, "fast", "after-migration", SetLLMAliasRequestPolicyInput{AllowedFields: []string{"store"}}); err != nil || r.Status != 200 {
		t.Fatal("request policy", err)
	}
	for _, bad := range []string{
		`UPDATE llm_model_aliases SET allowed_fields='{Store}' WHERE alias='fast'`,
		`UPDATE llm_model_aliases SET allowed_tool_types=ARRAY[NULL]::text[] WHERE alias='fast'`,
		`UPDATE llm_model_aliases SET max_output_tokens=0 WHERE alias='fast'`,
		`UPDATE llm_model_aliases SET output_cap_field='max' WHERE alias='fast'`,
	} {
		if _, err = p.s.pool.Exec(t.Context(), bad); err == nil {
			t.Fatal("the schema accepted", bad)
		}
	}
}
