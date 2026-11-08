package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

const providerSecret = "sk-test-0123456789-abcdef" // gitleaks:allow test fixture, not a credential

func createProvider(t *testing.T, l *tenantLab, p Principal, key string) LLMProvider {
	t.Helper()
	r, err := l.a.CreateLLMProvider(t.Context(), p, key, CreateLLMProviderInput{Name: "main-" + key, Kind: "openai_compatible", BaseURL: "https://llm.example.org/v1", Secret: providerSecret})
	var v LLMProvider
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &v) != nil {
		t.Fatal("create provider", err, r.Status)
	}
	return v
}

func TestLLMProviderSecretsStayWriteOnlyAndEncrypted(t *testing.T) {
	l, _, owner := agentLab(t)
	v := createProvider(t, l, owner, "p1")
	r, _ := l.a.CreateLLMProvider(t.Context(), owner, "p1", CreateLLMProviderInput{Name: "main-p1", Kind: "openai_compatible", BaseURL: "https://llm.example.org/v1", Secret: providerSecret})
	if !r.Replayed || bytes.Contains(r.Body, []byte(providerSecret)) {
		t.Fatal("replay failed or leaks", r.Replayed)
	}
	if _, err := l.a.CreateLLMProvider(t.Context(), owner, "p1", CreateLLMProviderInput{Name: "main-p1", Kind: "openai_compatible", BaseURL: "https://llm.example.org/v1", Secret: providerSecret + "x"}); !errors.Is(err, ErrConflict) {
		t.Fatal("same key with another secret accepted", err)
	}
	items, err := l.a.ListLLMProviders(t.Context(), owner, "", 50)
	if err != nil || len(items) != 1 {
		t.Fatal("list", err, len(items))
	}
	encoded, _ := json.Marshal(items)
	if bytes.Contains(encoded, []byte(providerSecret)) {
		t.Fatal("API view carries the credential")
	}
	// Ciphertext at rest does not contain the credential and is bound to its row.
	var raw []byte
	if err = l.s.pool.QueryRow(t.Context(), `SELECT secret_ciphertext FROM llm_providers WHERE id=$1`, v.ID).Scan(&raw); err != nil || bytes.Contains(raw, []byte(providerSecret)) || len(raw) < 28 {
		t.Fatal("credential stored in clear", err)
	}
	var dump string
	if err = l.s.pool.QueryRow(t.Context(), `SELECT string_agg(t::text,' ') FROM (SELECT * FROM llm_audit UNION ALL SELECT id,tenant_id,'','','',now(),'' FROM tenant_http_receipts LIMIT 0) t`).Scan(&dump); err == nil && strings.Contains(dump, providerSecret) {
		t.Fatal("credential in audit")
	}
	// Invalid inputs.
	for _, bad := range []CreateLLMProviderInput{
		{Name: "n", Kind: "openai_compatible", BaseURL: "http://llm.example.org/v1", Secret: providerSecret},
		{Name: "n", Kind: "openai_compatible", BaseURL: "https://u:p@llm.example.org/v1", Secret: providerSecret},
		{Name: "n", Kind: "other", BaseURL: "https://llm.example.org", Secret: providerSecret},
		{Name: "n", Kind: "anthropic", BaseURL: "https://llm.example.org", Secret: "short"},
	} {
		if _, err = l.a.CreateLLMProvider(t.Context(), owner, newID("k"), bad); !errors.Is(err, ErrInput) {
			t.Fatal("invalid provider accepted", bad.BaseURL, err)
		}
	}
	if _, err = l.a.CreateLLMProvider(t.Context(), owner, "local", CreateLLMProviderInput{Name: "ollama", Kind: "openai_compatible", BaseURL: "http://127.0.0.1:11434/v1", Secret: providerSecret}); err != nil {
		t.Fatal("loopback http refused", err)
	}
}

func TestLLMAdministrationNeedsScopeAndRole(t *testing.T) {
	l, _, owner := agentLab(t)
	addMember(t, l, owner, "operator", authorization.AgentOperator)
	op := agentPrincipal(t, l, "operator", agentScopes)
	if _, err := l.a.CreateLLMProvider(t.Context(), op, "k", CreateLLMProviderInput{Name: "n", Kind: "anthropic", BaseURL: "https://api.example.org", Secret: providerSecret}); !errors.Is(err, ErrForbidden) {
		t.Fatal("operator managed providers", err)
	}
	if _, err := l.a.ListLLMProviders(t.Context(), op, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatal("operator listed providers", err)
	}
	noScope := agentPrincipal(t, l, organizationInput().InitialOwner.Subject, "org:read")
	if _, err := l.a.CreateLLMProvider(t.Context(), noScope, "k", CreateLLMProviderInput{Name: "n", Kind: "anthropic", BaseURL: "https://api.example.org", Secret: providerSecret}); !errors.Is(err, ErrForbidden) {
		t.Fatal("scope-less credential managed providers", err)
	}
}

func TestLLMRotationAndDisableApplyToTheNextCall(t *testing.T) {
	l, _, owner := agentLab(t)
	v := createProvider(t, l, owner, "p1")
	var a1 LLMAlias
	r, err := l.a.CreateLLMAlias(t.Context(), owner, "a1", CreateLLMAliasInput{Alias: "fast", ProviderID: v.ID, UpstreamModel: "gpt-x"})
	if err != nil || json.Unmarshal(r.Body, &a1) != nil {
		t.Fatal("alias", err)
	}
	if _, err = l.a.CreateLLMAlias(t.Context(), owner, "a2", CreateLLMAliasInput{Alias: "fast", ProviderID: v.ID, UpstreamModel: "other"}); !errors.Is(err, ErrConflict) {
		t.Fatal("alias reused", err)
	}
	route, err := l.a.ResolveLLMRoute(t.Context(), owner.TenantID, "fast")
	if err != nil || route.Secret != providerSecret || route.UpstreamModel != "gpt-x" {
		t.Fatal("resolve", err)
	}
	// No alias, no route: the alias list is the model policy.
	if _, err = l.a.ResolveLLMRoute(t.Context(), owner.TenantID, "unlisted"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unlisted model resolved", err)
	}
	if _, err = l.a.RotateLLMProviderSecret(t.Context(), owner, v.ID, "rot1", "sk-rotated-9876543210"); err != nil {
		t.Fatal(err)
	}
	route, err = l.a.ResolveLLMRoute(t.Context(), owner.TenantID, "fast")
	if err != nil || route.Secret != "sk-rotated-9876543210" {
		t.Fatal("rotation not effective at once", err)
	}
	if _, err = l.a.DisableLLMProvider(t.Context(), owner, v.ID, "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.ResolveLLMRoute(t.Context(), owner.TenantID, "fast"); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled provider still resolves", err)
	}
	var n int
	if err = l.s.pool.QueryRow(t.Context(), `SELECT octet_length(secret_ciphertext) FROM llm_providers WHERE id=$1`, v.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal("ciphertext kept after disable", n, err)
	}
	if _, err = l.a.RotateLLMProviderSecret(t.Context(), owner, v.ID, "rot2", "sk-zombie-123456789"); !errors.Is(err, ErrTransition) {
		t.Fatal("disabled provider rotated back to life", err)
	}
	if _, err = l.a.CreateLLMAlias(t.Context(), owner, "a3", CreateLLMAliasInput{Alias: "again", ProviderID: v.ID, UpstreamModel: "m"}); !errors.Is(err, ErrTransition) {
		t.Fatal("alias on disabled provider", err)
	}
	page, err := l.a.ListAudit(t.Context(), owner, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range page.Items {
		seen[e.Action] = true
		if strings.Contains(e.Action+e.Target+e.Reference, providerSecret) {
			t.Fatal("credential in audit event")
		}
	}
	for _, want := range []string{"llm.provider.created", "llm.provider.rotated", "llm.provider.disabled", "llm.alias.created"} {
		if !seen[want] {
			t.Fatal("missing audit event", want)
		}
	}
}

func TestLLMRoutesDoNotCrossTenantsAndAliasDisableIsImmediate(t *testing.T) {
	l, _, owner := agentLab(t)
	v := createProvider(t, l, owner, "p1")
	if _, err := l.a.CreateLLMAlias(t.Context(), owner, "a1", CreateLLMAliasInput{Alias: "fast", ProviderID: v.ID, UpstreamModel: "m"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.ResolveLLMRoute(t.Context(), "org-someone-else", "fast"); !errors.Is(err, ErrNotFound) {
		t.Fatal("route crossed tenants", err)
	}
	if _, err := l.a.DisableLLMAlias(t.Context(), owner, "fast", "da"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.ResolveLLMRoute(t.Context(), owner.TenantID, "fast"); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled alias resolves", err)
	}
}
