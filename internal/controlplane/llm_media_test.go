package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

// mediaProvider is a fake openai_compatible upstream for embeddings,
// transcription and OCR. It reports the usage set in its fields (0 reports
// none) and hangs on a call while hang is set, so that the gateway cuts it.
type mediaProvider struct {
	calls    atomic.Int32
	tokens   atomic.Int64
	duration atomic.Value // string, the "duration" field; "" reports none
	pages    atomic.Int64
	hang     atomic.Bool
}

func (m *mediaProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.calls.Add(1)
	if m.hang.Load() {
		// Read the body first: the server sees the client go only then.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/embeddings"):
		var in struct{ Input []string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		data := []string{}
		for i := range in.Input {
			data = append(data, fmt.Sprintf(`{"index":%d,"embedding":[0.5,0.25]}`, i))
		}
		usage := ""
		if n := m.tokens.Load(); n > 0 {
			usage = fmt.Sprintf(`,"usage":{"prompt_tokens":%d}`, n)
		}
		_, _ = fmt.Fprintf(w, `{"data":[%s]%s}`, strings.Join(data, ","), usage)
	case strings.HasSuffix(r.URL.Path, "/audio/transcriptions"):
		duration, _ := m.duration.Load().(string)
		if duration != "" {
			duration = `,"duration":` + duration
		}
		_, _ = fmt.Fprintf(w, `{"text":"bonjour","segments":[{"start":0,"end":1.5,"text":"bonjour"}]%s}`, duration)
	case strings.HasSuffix(r.URL.Path, "/ocr"):
		usage := ""
		if n := m.pages.Load(); n > 0 {
			usage = fmt.Sprintf(`,"usage_info":{"pages_processed":%d}`, n)
		}
		_, _ = fmt.Fprintf(w, `{"pages":[{"index":0,"markdown":"# Page"}]%s}`, usage)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type mediaLab struct {
	*budgetLab
	upstream *mediaProvider
	provider string
	caller   VMCaller
}

// newMediaLab is a budget lab whose provider is a fake media upstream, and
// whose agent is placed on a VM that calls it. Its aliases: "fast" (chat,
// priced per token), "embed" (embed, 1 micro-unit per input token), "voice"
// (transcribe, 6,000 per minute), "ocr" (ocr, 2,000 per page) and "media"
// (the three, no unit prices).
func newMediaLab(t *testing.T) *mediaLab {
	t.Helper()
	l, c, owner := agentLab(t)
	fast := createProvider(t, l, owner, "bp")
	if _, err := l.a.CreateLLMAlias(t.Context(), owner, "al1", CreateLLMAliasInput{Alias: "fast", ProviderID: fast.ID, UpstreamModel: "m", InputMicroPerMTok: price(1_000_000), OutputMicroPerMTok: price(3_000_000)}); err != nil {
		t.Fatal(err)
	}
	b := &budgetLab{tenantLab: l, owner: owner, agent: activateTenantAgent(t, l, c, owner, "media-agent"), other: createTenantAgent(t, c, owner, "a2")}
	m := &mediaLab{budgetLab: b, upstream: &mediaProvider{}}
	m.upstream.duration.Store("")
	srv := httptest.NewServer(m.upstream)
	t.Cleanup(srv.Close)
	p := createProvider(t, b.tenantLab, b.owner, "media")
	m.provider = p.ID
	if _, err := b.s.pool.Exec(t.Context(), `UPDATE llm_providers SET base_url=$1`, srv.URL+"/v1"); err != nil {
		t.Fatal(err)
	}
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
	if err := b.s.RegisterPlacement(t.Context(), b.agent, "local"); err != nil {
		t.Log("placement already registered:", err)
	}
	pl, err := b.s.ClaimPlacement(t.Context(), b.agent, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", pl.Generation)
	if err = b.s.ConfirmPlacement(t.Context(), b.agent, "local", "worker", pl.Generation, vm); err != nil {
		t.Fatal(err)
	}
	m.caller = VMCaller{AgentID: b.agent, HostID: "local", VMID: vm, Generation: pl.Generation}
	return m
}

func (m *mediaLab) service(t *testing.T, timeout time.Duration) *LLMService {
	t.Helper()
	svc, err := NewLLMService(m.a, llmgateway.NewForTests(llmgateway.Config{Timeout: timeout, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

type mediaCall struct {
	State                       string
	Operation                   string
	Reserved, Seconds, Pages    int64
	SettledSeconds, SettledPage *int64
	Input, Output, Cost         *int64
	ReservedCost                int64
}

func (m *mediaLab) call(t *testing.T, key string) mediaCall {
	t.Helper()
	var c mediaCall
	if err := m.s.pool.QueryRow(t.Context(), `SELECT state,operation,reserved_tokens,reserved_audio_seconds,reserved_pages,audio_seconds,pages,input_tokens,output_tokens,
        estimated_cost_micro,reserved_cost_micro FROM llm_usage WHERE agent_id=$1 AND request_key=$2`, m.caller.AgentID, key).
		Scan(&c.State, &c.Operation, &c.Reserved, &c.Seconds, &c.Pages, &c.SettledSeconds, &c.SettledPage, &c.Input, &c.Output, &c.Cost, &c.ReservedCost); err != nil {
		t.Fatal(key, err)
	}
	return c
}

func (m *mediaLab) usageRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := m.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM llm_usage WHERE tenant_id=$1`, m.owner.TenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var (
	speech = llmgateway.TranscribeRequest{Audio: []byte("fake mp3"), Format: "mp3", DurationSeconds: 290, Language: "fr"}
	scan   = llmgateway.OCRRequest{Document: []byte("%PDF-1.7 fake"), MediaType: "application/pdf", Pages: 2}
	words  = llmgateway.EmbedRequest{Input: []string{"net present value", "discount rate"}}
)

// A route the alias does not declare is refused before any reservation, and
// so is a chat call to an alias that serves no chat.
func TestAnUndeclaredOperationIsRefusedBeforeAnyReservation(t *testing.T) {
	m := newMediaLab(t)
	svc := m.service(t, time.Second)
	for name, try := range map[string]func() error{
		"embed on a chat alias": func() error {
			_, err := svc.EmbedFromVM(t.Context(), m.caller, "k1", "fast", words, nil)
			return err
		},
		"transcribe on an embedding alias": func() error {
			_, err := svc.TranscribeFromVM(t.Context(), m.caller, "k2", "embed", speech, nil)
			return err
		},
		"ocr on a transcription alias": func() error {
			_, err := svc.OCRFromVM(t.Context(), m.caller, "k3", "voice", scan, nil)
			return err
		},
		"chat on an OCR alias": func() error {
			_, err := svc.CallFromVM(t.Context(), m.caller, "k4", "ocr", llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "hi"}}}, nil)
			return err
		},
		"native request on an embedding alias": func() error {
			_, err := svc.ForwardFromVM(t.Context(), m.caller, "k5", "embed", "openai", []byte(`{"messages":[{"role":"user","content":"hi"}]}`), nil)
			return err
		},
	} {
		err := try()
		var refused *LLMRefusal
		if !errors.Is(err, llmgateway.ErrUnsupported) || errors.Is(err, ErrBudgetExceeded) || !errors.As(err, &refused) || refused.Reason != "unsupported" {
			t.Fatal(name, err)
		}
	}
	if n := m.usageRows(t); n != 0 || m.upstream.calls.Load() != 0 {
		t.Fatal("a refused operation was reserved or sent", n, m.upstream.calls.Load())
	}
	// Existing aliases serve chat only, and so does an alias created without
	// operations.
	aliases, err := m.a.ListLLMAliases(t.Context(), m.owner, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range aliases {
		want := map[string][]string{"fast": {"chat"}, "embed": {"embed"}, "voice": {"transcribe"}, "ocr": {"ocr"}, "media": {"embed", "transcribe", "ocr"}}[a.Alias]
		if !slices.Equal(a.Operations, want) {
			t.Fatal(a.Alias, a.Operations)
		}
	}
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
	if _, err = m.a.reserveLLM(t.Context(), m.owner.TenantID, m.agent, "fast", "embed-now", llmAmounts{Operation: LLMEmbed, Input: 5}, nil); err != nil {
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

func TestEmbeddingsSettleTheProviderTokensAndCountInTokenBudgets(t *testing.T) {
	m := newMediaLab(t)
	svc := m.service(t, time.Second)
	m.upstream.tokens.Store(9)
	out, err := svc.EmbedFromVM(t.Context(), m.caller, "e1", "embed", words, nil)
	if err != nil || out.Dimensions != 2 || len(out.Embeddings) != 2 || out.Usage.InputTokens != 9 {
		t.Fatal(out, err)
	}
	if c := m.call(t, "e1"); c.State != "settled" || c.Operation != "embed" || *c.Input != 9 || *c.Output != 0 || *c.Cost != 9 || c.Reserved != 11 {
		t.Fatalf("%+v", c)
	}
	// A provider that reports no usage is settled on the reservation.
	m.upstream.tokens.Store(0)
	if out, err = svc.EmbedFromVM(t.Context(), m.caller, "e2", "embed", words, nil); err != nil || out.Usage.InputTokens != 11 {
		t.Fatal(out, err)
	}
	if c := m.call(t, "e2"); c.State != "settled" || *c.Input != 11 {
		t.Fatalf("%+v", c)
	}
	// A settled key never calls the provider again.
	before := m.upstream.calls.Load()
	if _, err = svc.EmbedFromVM(t.Context(), m.caller, "e1", "embed", words, nil); !errors.Is(err, ErrLLMAlreadyProcessed) || m.upstream.calls.Load() != before {
		t.Fatal("a settled key was replayed", err)
	}
	// So is a key that names a call of another operation, untouched.
	if _, err = svc.TranscribeFromVM(t.Context(), m.caller, "e1", "media", speech, nil); !errors.Is(err, ErrLLMAlreadyProcessed) || m.call(t, "e1").Operation != "embed" {
		t.Fatal("a key reused across operations", err)
	}
	// Token budgets count embedding tokens: 9 + 11 = 20 of 30; the next
	// reservation of 11 does not fit.
	m.budget(t, "tok", CreateLLMBudgetInput{Alias: "embed", Period: "day", LimitTokens: 30, Mode: "hard"})
	if _, err = svc.EmbedFromVM(t.Context(), m.caller, "e3", "embed", words, nil); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatal("a hard token budget let an embedding through", err)
	}
	rep, err := m.a.LLMUsage(t.Context(), m.owner, "day")
	if err != nil || rep.Totals.SettledInput != 20 || rep.Totals.SettledOutput != 0 || rep.Totals.EstimatedCostMicro != 20 {
		t.Fatalf("usage %+v %v", rep.Totals, err)
	}
}

func TestTranscriptionCountsSecondsInCostBudgetsOnly(t *testing.T) {
	m := newMediaLab(t)
	svc := m.service(t, time.Second)
	// A token budget already past its limit does not stop a transcription.
	if _, err := m.a.ReserveLLM(t.Context(), m.owner.TenantID, m.agent, "fast", "spent", 11, 0); err != nil {
		t.Fatal(err)
	}
	m.budget(t, "tok", CreateLLMBudgetInput{Period: "day", LimitTokens: 10, Mode: "hard"})
	m.budget(t, "cost", CreateLLMBudgetInput{Alias: "voice", Period: "day", LimitCostMicro: 30_000, Mode: "hard"})
	m.upstream.duration.Store("287.2")
	out, err := svc.TranscribeFromVM(t.Context(), m.caller, "t1", "voice", speech, nil)
	if err != nil || out.Text != "bonjour" || out.DurationSeconds != 288 || len(out.Segments) != 1 {
		t.Fatal(out, err)
	}
	// 290 s reserved at 6,000 per minute is 29,000; 288 s settled is 28,800.
	c := m.call(t, "t1")
	if c.State != "settled" || c.Operation != "transcribe" || c.Reserved != 0 || c.Seconds != 290 || c.ReservedCost != 29_000 ||
		*c.SettledSeconds != 288 || *c.Cost != 28_800 || *c.Input != 0 || *c.Output != 0 || c.SettledPage != nil {
		t.Fatalf("%+v", c)
	}
	// 28,800 + 20 s (2,000) is past 30,000: refused before the provider.
	before := m.upstream.calls.Load()
	short := speech
	short.DurationSeconds = 20
	if _, err = svc.TranscribeFromVM(t.Context(), m.caller, "t2", "voice", short, nil); !errors.Is(err, ErrBudgetExceeded) || m.upstream.calls.Load() != before {
		t.Fatal("a hard cost budget let a transcription through", err)
	}
	// 11 s (1,100) fits; the provider reports no duration, so the declared
	// duration is settled.
	m.upstream.duration.Store("")
	short.DurationSeconds = 11
	if out, err = svc.TranscribeFromVM(t.Context(), m.caller, "t3", "voice", short, nil); err != nil || out.DurationSeconds != 11 {
		t.Fatal(out, err)
	}
	if c = m.call(t, "t3"); *c.SettledSeconds != 11 || *c.Cost != 1100 {
		t.Fatalf("%+v", c)
	}
	// An alias without an audio price is unpriced for this unit: a hard cost
	// budget refuses it, a soft one lets it through.
	m.budget(t, "media-soft", CreateLLMBudgetInput{Alias: "media", Period: "month", LimitCostMicro: 1, Mode: "soft"})
	if _, err = svc.TranscribeFromVM(t.Context(), m.caller, "t4", "media", short, nil); err != nil {
		t.Fatal("a soft cost budget refused an unpriced transcription", err)
	}
	m.budget(t, "media-hard", CreateLLMBudgetInput{Alias: "media", Period: "day", LimitCostMicro: 1_000_000, Mode: "hard"})
	_, err = svc.TranscribeFromVM(t.Context(), m.caller, "t5", "media", short, nil)
	if !errors.Is(err, ErrBudgetExceeded) || m.refusal(t, err).Reason != "unpriced" {
		t.Fatal("a hard cost budget let an unpriced transcription through", err)
	}
	rep, err := m.a.LLMUsage(t.Context(), m.owner, "day")
	if err != nil || rep.Totals.SettledAudioSeconds != 288+11+11 || rep.Totals.SettledPages != 0 || rep.Totals.SettledInput != 0 || rep.Totals.EstimatedCostMicro != 29_900 {
		t.Fatalf("usage %+v %v", rep.Totals, err)
	}
}

func TestOCRCountsPagesAtThePriceOfItsReservation(t *testing.T) {
	m := newMediaLab(t)
	svc := m.service(t, time.Second)
	m.upstream.pages.Store(3)
	out, err := svc.OCRFromVM(t.Context(), m.caller, "o1", "ocr", scan, nil)
	if err != nil || out.PagesProcessed != 3 || len(out.Pages) != 1 || out.Pages[0].Markdown != "# Page" {
		t.Fatal(out, err)
	}
	// A price change applies to the calls reserved after it.
	if _, err = m.a.SetLLMAliasPrices(t.Context(), m.owner, "ocr", "p1", SetLLMAliasPricesInput{InputMicroPerMTok: price(0), OutputMicroPerMTok: price(0), OCRMicroPerPage: price(5000)}); err != nil {
		t.Fatal(err)
	}
	c := m.call(t, "o1")
	if c.State != "settled" || c.Operation != "ocr" || c.Pages != 2 || c.ReservedCost != 4000 || *c.SettledPage != 3 || *c.Cost != 6000 || c.SettledSeconds != nil {
		t.Fatalf("%+v", c)
	}
	m.upstream.pages.Store(0)
	if out, err = svc.OCRFromVM(t.Context(), m.caller, "o2", "ocr", scan, nil); err != nil || out.PagesProcessed != 2 {
		t.Fatal(out, err)
	}
	if c = m.call(t, "o2"); *c.SettledPage != 2 || *c.Cost != 10_000 {
		t.Fatalf("%+v", c)
	}
	rep, err := m.a.LLMUsage(t.Context(), m.owner, "day")
	if err != nil || rep.Totals.SettledPages != 5 || rep.Totals.EstimatedCostMicro != 16_000 || len(rep.Lines) != 1 || rep.Lines[0].SettledPages != 5 {
		t.Fatalf("usage %+v %v", rep, err)
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

// A call cut after it was sent stays counted as unknown, and the organization
// reconciles it in its own unit.
func TestMediaCallCutAfterSendingIsUnknownAndReconcilable(t *testing.T) {
	m := newMediaLab(t)
	m.upstream.hang.Store(true)
	cut := m.service(t, 50*time.Millisecond)
	if _, err := cut.TranscribeFromVM(t.Context(), m.caller, "cut-t", "voice", speech, nil); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("a transcription cut after sending is not uncertain", err)
	}
	if _, err := cut.OCRFromVM(t.Context(), m.caller, "cut-o", "ocr", scan, nil); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if _, err := cut.EmbedFromVM(t.Context(), m.caller, "cut-e", "embed", words, nil); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	m.upstream.hang.Store(false)
	if m.upstream.calls.Load() != 3 {
		t.Fatal("a cut call was retried", m.upstream.calls.Load())
	}
	// The same key never reaches the provider again.
	if _, err := m.service(t, time.Second).TranscribeFromVM(t.Context(), m.caller, "cut-t", "voice", speech, nil); !errors.Is(err, ErrLLMAlreadyProcessed) || m.upstream.calls.Load() != 3 {
		t.Fatal("an uncertain key was sent again", err)
	}
	// The reservations keep counting: 29,000 for 290 s, 4,000 for 2 pages.
	rep, err := m.a.LLMUsage(t.Context(), m.owner, "day")
	if err != nil || rep.Totals.UnknownCostMicro != 29_000+4_000+11 || rep.Totals.UnknownTokens != 11 {
		t.Fatalf("usage %+v %v", rep.Totals, err)
	}
	calls, err := m.a.ListLLMUnresolved(t.Context(), m.owner, "", 10)
	if err != nil || len(calls) != 3 {
		t.Fatal(calls, err)
	}
	ids := map[string]LLMCall{}
	for _, c := range calls {
		ids[c.Operation] = c
	}
	if c := ids["transcribe"]; c.ReservedAudioSeconds != 290 || c.ReservedTokens != 0 || c.ReservedCostMicro != 29_000 || ids["ocr"].ReservedPages != 2 {
		t.Fatalf("%+v", calls)
	}
	// Settled in the call's unit only.
	transcription := ids["transcribe"].ID
	if _, err = m.a.SettleLLMOutcome(t.Context(), m.owner, transcription, "s0", SettleLLMOutcomeInput{InputTokens: 100}); !errors.Is(err, ErrInput) {
		t.Fatal("a transcription settled in tokens", err)
	}
	if _, err = m.a.SettleLLMOutcome(t.Context(), m.owner, ids["embed"].ID, "s1", SettleLLMOutcomeInput{InputTokens: 7, OutputTokens: 1}); !errors.Is(err, ErrInput) {
		t.Fatal("an embedding settled with output tokens", err)
	}
	r, err := m.a.SettleLLMOutcome(t.Context(), m.owner, transcription, "s2", SettleLLMOutcomeInput{AudioSeconds: 120})
	var settled LLMCall
	if err != nil || json.Unmarshal(r.Body, &settled) != nil || settled.State != "settled" || *settled.AudioSeconds != 120 || *settled.EstimatedCostMicro != 12_000 {
		t.Fatal("settle", err, string(r.Body))
	}
	if again, err := m.a.SettleLLMOutcome(t.Context(), m.owner, transcription, "s2", SettleLLMOutcomeInput{AudioSeconds: 120}); err != nil || !again.Replayed {
		t.Fatal("replay of a settlement", err)
	}
	if _, err = m.a.SettleLLMOutcome(t.Context(), m.owner, ids["ocr"].ID, "s3", SettleLLMOutcomeInput{Pages: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = m.a.ReleaseLLMOutcome(t.Context(), m.owner, ids["embed"].ID, "s4"); err != nil {
		t.Fatal(err)
	}
	rep, err = m.a.LLMUsage(t.Context(), m.owner, "day")
	if err != nil || rep.Totals.UnknownCostMicro != 0 || rep.Totals.SettledAudioSeconds != 120 || rep.Totals.SettledPages != 1 || rep.Totals.EstimatedCostMicro != 14_000 {
		t.Fatalf("usage %+v %v", rep.Totals, err)
	}
	var audited int
	if err = m.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM llm_audit WHERE action IN ('usage.settled','usage.released')`).Scan(&audited); err != nil || audited != 3 {
		t.Fatal("reconciliation audit", audited, err)
	}
}

// A reservation left "reserved" by a worker that died before its outcome is
// uncertain when its key comes back: it is never sent again.
func TestMediaKeyLeftReservedComesBackUnknown(t *testing.T) {
	m := newMediaLab(t)
	if _, err := m.a.reserveLLM(t.Context(), m.owner.TenantID, m.agent, "ocr", "orphan", llmAmounts{Operation: LLMOCR, Pages: 2}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.service(t, time.Second).OCRFromVM(t.Context(), m.caller, "orphan", "ocr", scan, nil); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if c := m.call(t, "orphan"); c.State != "unknown" || m.upstream.calls.Load() != 0 {
		t.Fatalf("%+v %d", c, m.upstream.calls.Load())
	}
}

func TestOperationAmountsAndCosts(t *testing.T) {
	for i, c := range []struct {
		q           llmAmounts
		reservation bool
		ok          bool
	}{
		{llmAmounts{Operation: LLMChat, Input: 1}, true, true},
		{llmAmounts{Operation: LLMChat}, true, false},
		{llmAmounts{Operation: LLMChat}, false, true},
		{llmAmounts{Operation: LLMChat, Input: 1, Pages: 1}, true, false},
		{llmAmounts{Operation: LLMEmbed, Input: 1, Output: 1}, true, false},
		{llmAmounts{Operation: LLMTranscribe, AudioSeconds: 1}, true, true},
		{llmAmounts{Operation: LLMTranscribe, AudioSeconds: 1, Input: 1}, true, false},
		{llmAmounts{Operation: LLMTranscribe}, false, true},
		{llmAmounts{Operation: LLMOCR, Pages: 1}, true, true},
		{llmAmounts{Operation: LLMOCR, Pages: 2e9}, false, false},
		{llmAmounts{Operation: LLMVision, Input: 1}, true, false},
		{llmAmounts{Operation: LLMChat, Input: -1}, false, false},
	} {
		if c.q.valid(c.reservation) != c.ok {
			t.Fatal(i, c)
		}
	}
	p := llmPrices{input: 1_000_000, output: 3_000_000, audioPerMinute: 7, perPage: 11}
	for q, want := range map[llmAmounts]int64{
		{Operation: LLMEmbed, Input: 5}:              5,
		{Operation: LLMChat, Input: 1, Output: 1}:    4,
		{Operation: LLMTranscribe, AudioSeconds: 1}:  1, // 7/60 rounded up
		{Operation: LLMTranscribe, AudioSeconds: 60}: 7,
		{Operation: LLMTranscribe, AudioSeconds: 61}: 8,
		{Operation: LLMOCR, Pages: 3}:                33,
	} {
		if got, ok := p.cost(q); !ok || got != want {
			t.Fatal(q, got, want)
		}
	}
	if _, ok := (llmPrices{audioPerMinute: 1e12}).cost(llmAmounts{Operation: LLMTranscribe, AudioSeconds: 1e12}); ok {
		t.Fatal("an overflow was priced")
	}
}
