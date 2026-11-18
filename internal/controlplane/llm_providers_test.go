package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
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
	// The audit records the creation once, by its actor, without the
	// credential; the stored receipt does not carry it either.
	var created int
	var dump string
	if err = l.s.pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE action='provider.created' AND provider_id=$2 AND actor_principal_id=$3), coalesce(string_agg(a::text,' '),'')
        FROM llm_audit a WHERE tenant_id=$1`, owner.TenantID, v.ID, owner.ID).Scan(&created, &dump); err != nil || created != 1 || strings.Contains(dump, providerSecret) {
		t.Fatal("creation not audited once, or credential in audit", err, created)
	}
	var receipt []byte
	if err = l.s.pool.QueryRow(t.Context(), `SELECT response_ciphertext FROM tenant_http_receipts WHERE tenant_id=$1 AND operation='llm.provider.create' AND key='p1'`, owner.TenantID).Scan(&receipt); err != nil || bytes.Contains(receipt, []byte(providerSecret)) {
		t.Fatal("receipt missing or carries the credential", err)
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

// An https URL that names an internal address directly is refused at
// registration with its own error: the worker would refuse to call it. A
// model server on the operator's network is registered by its name.
func TestLLMProviderURLNamingAnInternalAddressIsRefused(t *testing.T) {
	l, _, owner := agentLab(t)
	for _, base := range []string{"https://127.0.0.1:11434/v1", "https://[::1]/v1", "https://10.0.0.7/v1", "https://172.16.4.4", "https://192.168.1.20:8443",
		"https://[fd12::7]/v1", "https://100.64.0.9", "https://169.254.169.254/latest", "https://[fd00:ec2::254]", "https://168.63.129.16",
		"https://0.0.0.0", "https://[::ffff:10.0.0.7]", "https://localhost:11434/v1", "https://models.localhost", "https://127.1", "https://2130706433"} {
		_, err := l.a.CreateLLMProvider(t.Context(), owner, newID("k"), CreateLLMProviderInput{Name: newID("internal"), Kind: "openai_compatible", BaseURL: base, Secret: providerSecret})
		if !errors.Is(err, ErrProviderAddress) || !errors.Is(err, ErrInput) {
			t.Error(base, "accepted or mistyped:", err)
		}
	}
	for i, base := range []string{"https://models.corp.example:11434/v1", "https://1.1.1.1/v1", "https://api.anthropic.com"} {
		if _, err := l.a.CreateLLMProvider(t.Context(), owner, newID("k"), CreateLLMProviderInput{Name: "public-" + strconv.Itoa(i), Kind: "anthropic", BaseURL: base, Secret: providerSecret}); err != nil {
			t.Error(base, "refused:", err)
		}
	}
	items, err := l.a.ListLLMProviders(t.Context(), owner, "", 50)
	if err != nil || len(items) != 3 {
		t.Fatal("a refused provider was stored", err, len(items))
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
