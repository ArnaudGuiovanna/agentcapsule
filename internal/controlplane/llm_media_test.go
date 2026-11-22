package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// mediaLab is a budget lab with the aliases of the LLM service's media tests
// (internal/llmservice/media_test.go), without the provider they call: "fast"
// (chat, priced per token), "embed" (embed, 1 micro-unit per input token),
// "voice" (transcribe, 6,000 per minute), "ocr" (ocr, 2,000 per page) and
// "media" (the three, no unit prices). What an alias serves and costs is the
// control plane's; the calls are the service's.
type mediaLab struct {
	*budgetLab
	provider string
}

func newMediaLab(t *testing.T) *mediaLab {
	t.Helper()
	l, c, owner := agentLab(t)
	fast := createProvider(t, l, owner, "bp")
	if _, err := l.a.CreateLLMAlias(t.Context(), owner, "al1", CreateLLMAliasInput{Alias: "fast", ProviderID: fast.ID, UpstreamModel: "m", InputMicroPerMTok: price(1_000_000), OutputMicroPerMTok: price(3_000_000)}); err != nil {
		t.Fatal(err)
	}
	b := &budgetLab{tenantLab: l, owner: owner, agent: activateTenantAgent(t, l, c, owner, "media-agent"), other: createTenantAgent(t, c, owner, "a2")}
	m := &mediaLab{budgetLab: b}
	p := createProvider(t, b.tenantLab, b.owner, "media")
	m.provider = p.ID
	for _, a := range []CreateLLMAliasInput{
		{Alias: "embed", Operations: []string{"embed"}, InputMicroPerMTok: price(1_000_000), OutputMicroPerMTok: price(0)},
		{Alias: "voice", Operations: []string{"transcribe"}, AudioMicroPerMinute: price(6000)},
		{Alias: "ocr", Operations: []string{"ocr"}, OCRMicroPerPage: price(2000)},
		{Alias: "media", Operations: []string{"ocr", "transcribe", "embed"}},
	} {
		a.ProviderID, a.UpstreamModel = p.ID, "m-"+a.Alias
		if _, err := b.a.CreateLLMAlias(t.Context(), b.owner, "alias-"+a.Alias, a); err != nil {
			t.Fatal(a.Alias, err)
		}
	}
	return m
}

func TestAliasOperationsAreValidatedAuditedAndApplyFromTheNextReservation(t *testing.T) {
	m := newMediaLab(t)
	set := func(key, alias string, ops ...string) (APIReceipt, error) {
		return m.a.SetLLMAliasOperations(t.Context(), m.owner, alias, key, SetLLMAliasOperationsInput{Operations: ops})
	}
	for i, bad := range [][]string{nil, {}, {"chat", "chat"}, {"speak"}, {"chat", "vision", "embed", "transcribe", "ocr", "chat"}} {
		if _, err := set(fmt.Sprint("bad", i), "fast", bad...); !errors.Is(err, ErrInput) {
			t.Fatal("invalid operations accepted", bad, err)
		}
	}
	if _, err := set("missing", "nope", "chat"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	r, err := set("s1", "fast", "vision", "embed", "chat")
	var v LLMAlias
	if err != nil || r.Status != 200 || json.Unmarshal(r.Body, &v) != nil || !slices.Equal(v.Operations, []string{"chat", "vision", "embed"}) {
		t.Fatal("set operations", err, string(r.Body))
	}
	if again, err := set("s1", "fast", "chat", "vision", "embed"); err != nil || !again.Replayed {
		t.Fatal("the same key and set in another order is not a replay", err)
	}
	if _, err = m.a.ReserveLLM(t.Context(), m.owner.TenantID, m.agent, "fast", "embed-now", 0, 0); !errors.Is(err, ErrInput) {
		t.Fatal(err)
	}
	if _, err = m.a.reserveLLM(t.Context(), m.owner.TenantID, m.agent, "fast", "embed-now", LLMAmounts{Operation: LLMEmbed, Input: 5}, nil); err != nil {
		t.Fatal("an operation added was not served", err)
	}
	if r, err = set("s2", "fast", "chat", "embed", "vision"); err != nil || r.Status != 200 {
		t.Fatal("an unchanged set", err)
	}
	// Embeddings, transcription and OCR need an openai_compatible provider.
	pr, err := m.a.CreateLLMProvider(t.Context(), m.owner, "ant", CreateLLMProviderInput{Name: "claude", Kind: "anthropic", BaseURL: "https://api.anthropic.example", Secret: providerSecret})
	var anthropic LLMProvider
	if err != nil || json.Unmarshal(pr.Body, &anthropic) != nil {
		t.Fatal(err)
	}
	if _, err = m.a.CreateLLMAlias(t.Context(), m.owner, "a1", CreateLLMAliasInput{Alias: "claude", ProviderID: anthropic.ID, UpstreamModel: "c", Operations: []string{"chat", "embed"}}); !errors.Is(err, ErrInput) {
		t.Fatal("an anthropic alias serving embeddings", err)
	}
	if _, err = m.a.CreateLLMAlias(t.Context(), m.owner, "a2", CreateLLMAliasInput{Alias: "claude", ProviderID: anthropic.ID, UpstreamModel: "c", Operations: []string{"vision", "chat"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = set("s3", "claude", "chat", "ocr"); !errors.Is(err, ErrInput) {
		t.Fatal("an anthropic alias serving OCR", err)
	}
	if _, err = m.a.DisableLLMAlias(t.Context(), m.owner, "voice", "off"); err != nil {
		t.Fatal(err)
	}
	if _, err = set("s4", "voice", "transcribe", "embed"); !errors.Is(err, ErrTransition) {
		t.Fatal("a disabled alias changed", err)
	}
	var actions []string
	rows, err := m.s.pool.Query(t.Context(), `SELECT action||':'||coalesce(alias,'') FROM llm_audit WHERE action='alias.operations_set' ORDER BY created_at,id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	if fmt.Sprint(actions) != "[alias.operations_set:fast]" {
		t.Fatal("audit", actions)
	}
}

func TestAliasUnitPricesAreSetReplacedAndAudited(t *testing.T) {
	m := newMediaLab(t)
	set := func(key string, in SetLLMAliasPricesInput) LLMAlias {
		t.Helper()
		r, err := m.a.SetLLMAliasPrices(t.Context(), m.owner, "media", key, in)
		var v LLMAlias
		if err != nil || json.Unmarshal(r.Body, &v) != nil {
			t.Fatal(err)
		}
		return v
	}
	v := set("p1", SetLLMAliasPricesInput{InputMicroPerMTok: price(1), OutputMicroPerMTok: price(2), AudioMicroPerMinute: price(600), OCRMicroPerPage: price(0)})
	if !v.Priced || *v.AudioMicroPerMinute != 600 || *v.OCRMicroPerPage != 0 {
		t.Fatalf("%+v", v)
	}
	// The body is the whole price list: a unit price left out is unpriced.
	if v = set("p2", SetLLMAliasPricesInput{InputMicroPerMTok: price(1), OutputMicroPerMTok: price(2)}); v.AudioMicroPerMinute != nil || v.OCRMicroPerPage != nil {
		t.Fatalf("%+v", v)
	}
	set("p3", SetLLMAliasPricesInput{InputMicroPerMTok: price(1), OutputMicroPerMTok: price(2)})
	if _, err := m.a.SetLLMAliasPrices(t.Context(), m.owner, "media", "p4", SetLLMAliasPricesInput{InputMicroPerMTok: price(1), OutputMicroPerMTok: price(2), OCRMicroPerPage: price(-1)}); !errors.Is(err, ErrInput) {
		t.Fatal(err)
	}
	var n int
	if err := m.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM llm_audit WHERE action='alias.prices_set' AND alias='media'`).Scan(&n); err != nil || n != 2 {
		t.Fatal("an unchanged price list was audited", n, err)
	}
}
