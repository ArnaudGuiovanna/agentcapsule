//go:build llmlive

package controlplane

// End-to-end metered embeddings, transcription and OCR against real
// providers (ADR 023 §12), with PostgreSQL as for every store test. The
// variables are those of internal/llmgateway/media_live_test.go. A counting
// reverse proxy sits between the gateway and the provider, so the tests can
// prove what is sent.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
)

type mediaLiveLab struct {
	*tenantLab
	owner  Principal
	caller VMCaller
	sent   *atomic.Int32
}

// newMediaLiveLab registers the provider at base, through a counting proxy,
// and the alias, for an agent placed on a VM.
func newMediaLiveLab(t *testing.T, base, secret string, alias CreateLLMAliasInput) *mediaLiveLab {
	t.Helper()
	if base == "" || alias.UpstreamModel == "" {
		t.Fatal("-tags llmlive needs the provider's base URL and model (see internal/llmgateway/media_live_test.go)")
	}
	upstream, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	sent := &atomic.Int32{}
	target := &url.URL{Scheme: upstream.Scheme, Host: upstream.Host}
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) },
		// A call the gateway cuts on purpose is not a proxy failure worth logging.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusBadGateway) }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	l, c, owner := agentLab(t)
	mode := "none"
	if secret != "" {
		mode = "secret"
	}
	r, err := l.a.CreateLLMProvider(t.Context(), owner, "live", CreateLLMProviderInput{AuthMode: mode, Name: "media-provider", Kind: "openai_compatible",
		BaseURL: srv.URL + strings.TrimRight(upstream.Path, "/"), Secret: secret})
	var p LLMProvider
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &p) != nil {
		t.Fatal("create provider", err)
	}
	alias.ProviderID = p.ID
	if _, err = l.a.CreateLLMAlias(t.Context(), owner, "alias-"+alias.Alias, alias); err != nil {
		t.Fatal(err)
	}
	agent := activateTenantAgent(t, l, c, owner, "media-live-agent")
	if err = l.s.RegisterPlacement(t.Context(), agent, "local"); err != nil {
		t.Log("placement already registered:", err)
	}
	pl, err := l.s.ClaimPlacement(t.Context(), agent, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", pl.Generation)
	if err = l.s.ConfirmPlacement(t.Context(), agent, "local", "worker", pl.Generation, vm); err != nil {
		t.Fatal(err)
	}
	return &mediaLiveLab{tenantLab: l, owner: owner, caller: VMCaller{AgentID: agent, HostID: "local", VMID: vm, Generation: pl.Generation}, sent: sent}
}

func (l *mediaLiveLab) service(t *testing.T, timeout time.Duration) *LLMService {
	t.Helper()
	svc, err := NewLLMService(l.a, llmgateway.NewForTests(llmgateway.Config{Timeout: timeout, MaxAttempts: 1}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (l *mediaLiveLab) state(t *testing.T, key string) string {
	t.Helper()
	var state string
	if err := l.s.pool.QueryRow(t.Context(), `SELECT state FROM llm_usage WHERE agent_id=$1 AND request_key=$2`, l.caller.AgentID, key).Scan(&state); err != nil {
		t.Fatal(key, err)
	}
	return state
}

func (l *mediaLiveLab) usage(t *testing.T) LLMUsageTotals {
	t.Helper()
	rep, err := l.a.LLMUsage(t.Context(), l.owner, "day")
	if err != nil {
		t.Fatal(err)
	}
	return rep.Totals
}

func newEmbedLiveLab(t *testing.T) *mediaLiveLab {
	return newMediaLiveLab(t, os.Getenv("AGENTCAPSULE_TEST_LLM_BASE_URL"), os.Getenv("AGENTCAPSULE_TEST_LLM_SECRET"), CreateLLMAliasInput{
		Alias: "embed", UpstreamModel: os.Getenv("AGENTCAPSULE_TEST_EMBED_MODEL"), Operations: []string{"embed"},
		InputMicroPerMTok: price(1_000_000), OutputMicroPerMTok: price(0)})
}

func TestEmbedLiveCallIsSettledAtTheProviderTokens(t *testing.T) {
	l := newEmbedLiveLab(t)
	svc := l.service(t, 2*time.Minute)
	q := llmgateway.EmbedRequest{Input: []string{"What is the net present value?", "Discount the cash flows at the cost of capital."}}
	out, err := svc.EmbedFromVM(t.Context(), l.caller, "live-1", "embed", q, nil)
	if err != nil || len(out.Embeddings) != 2 || out.Dimensions < 1 || out.Usage.InputTokens <= 0 {
		t.Fatal("the capsule's embedding failed", err, out.Dimensions, out.Usage)
	}
	if l.state(t, "live-1") != "settled" {
		t.Fatal("an answered call was not settled")
	}
	u := l.usage(t)
	if u.SettledInput != out.Usage.InputTokens || u.SettledOutput != 0 || u.EstimatedCostMicro != out.Usage.InputTokens || u.PendingTokens != 0 {
		t.Fatalf("usage %+v does not match the provider's %+v", u, out.Usage)
	}
	before := l.sent.Load()
	if _, err = svc.EmbedFromVM(t.Context(), l.caller, "live-1", "embed", q, nil); !errors.Is(err, ErrLLMAlreadyProcessed) || l.sent.Load() != before {
		t.Fatal("a settled key was sent again", err)
	}
	if _, err = svc.TranscribeFromVM(t.Context(), l.caller, "live-2", "embed", llmgateway.TranscribeRequest{Audio: []byte("x"), Format: "wav", DurationSeconds: 1}, nil); !errors.Is(err, llmgateway.ErrUnsupported) || l.sent.Load() != before {
		t.Fatal("an operation the alias does not declare was sent", err)
	}
	t.Logf("%d vectors of %d dimensions; %d input tokens settled", len(out.Embeddings), out.Dimensions, u.SettledInput)
}

// A batch cut while the provider computes it stays counted as unknown, and
// the organization settles it from its provider's figures.
func TestEmbedLiveCutAfterSendingIsUnknownAndReconcilable(t *testing.T) {
	l := newEmbedLiveLab(t)
	if _, err := l.service(t, 2*time.Minute).EmbedFromVM(t.Context(), l.caller, "warm", "embed", llmgateway.EmbedRequest{Input: []string{"warm up"}}, nil); err != nil {
		t.Fatal("warm-up", err)
	}
	long := make([]string, llmgateway.MaxEmbedInputs)
	for i := range long {
		long[i] = strings.Repeat(fmt.Sprintf("word%d ", i), 600)
	}
	sent := l.sent.Load()
	if _, err := l.service(t, 300*time.Millisecond).EmbedFromVM(t.Context(), l.caller, "cut", "embed", llmgateway.EmbedRequest{Input: long}, nil); !errors.Is(err, llmgateway.ErrOutcomeUnknown) {
		t.Fatal("a batch cut after sending was not uncertain", err)
	}
	if l.sent.Load() != sent+1 || l.state(t, "cut") != "unknown" {
		t.Fatal("a cut call was retried or not kept as unknown", l.sent.Load()-sent)
	}
	if u := l.usage(t); u.UnknownTokens <= 0 || u.UnknownCostMicro <= 0 {
		t.Fatalf("an uncertain call is no longer counted: %+v", u)
	}
	calls, err := l.a.ListLLMUnresolved(t.Context(), l.owner, "", 10)
	if err != nil || len(calls) != 1 || calls[0].Operation != "embed" {
		t.Fatal(calls, err)
	}
	if _, err = l.a.SettleLLMOutcome(t.Context(), l.owner, calls[0].ID, "settle", SettleLLMOutcomeInput{InputTokens: 16384}); err != nil {
		t.Fatal(err)
	}
	if u := l.usage(t); u.UnknownTokens != 0 || l.state(t, "cut") != "settled" {
		t.Fatalf("reconciliation %+v", u)
	}
}

func TestTranscribeLiveCallIsSettledAtTheProviderDuration(t *testing.T) {
	l := newMediaLiveLab(t, os.Getenv("AGENTCAPSULE_TEST_TRANSCRIBE_BASE_URL"), os.Getenv("AGENTCAPSULE_TEST_TRANSCRIBE_SECRET"), CreateLLMAliasInput{
		Alias: "voice", UpstreamModel: os.Getenv("AGENTCAPSULE_TEST_TRANSCRIBE_MODEL"), Operations: []string{"transcribe"}, AudioMicroPerMinute: price(6000)})
	q := liveSpeech(t)
	out, err := l.service(t, 2*time.Minute).TranscribeFromVM(t.Context(), l.caller, "live-t", "voice", q, nil)
	if err != nil || out.DurationSeconds < 1 || out.DurationSeconds > int64(q.DurationSeconds)+1 {
		t.Fatal("the capsule's transcription failed", err, out.DurationSeconds)
	}
	u := l.usage(t)
	if l.state(t, "live-t") != "settled" || u.SettledAudioSeconds != out.DurationSeconds || u.EstimatedCostMicro != out.DurationSeconds*100 || u.SettledInput != 0 || l.sent.Load() != 1 {
		t.Fatalf("usage %+v, %d s reported, %d requests", u, out.DurationSeconds, l.sent.Load())
	}
	t.Logf("transcript of %d bytes; %d s settled", len(out.Text), u.SettledAudioSeconds)
}

func TestOCRLiveCallIsSettledAtTheProviderPages(t *testing.T) {
	l := newMediaLiveLab(t, os.Getenv("AGENTCAPSULE_TEST_OCR_BASE_URL"), os.Getenv("AGENTCAPSULE_TEST_OCR_SECRET"), CreateLLMAliasInput{
		Alias: "ocr", UpstreamModel: os.Getenv("AGENTCAPSULE_TEST_OCR_MODEL"), Operations: []string{"ocr"}, OCRMicroPerPage: price(2000)})
	out, err := l.service(t, 2*time.Minute).OCRFromVM(t.Context(), l.caller, "live-o", "ocr", llmgateway.OCRRequest{Document: livePDF(), MediaType: "application/pdf", Pages: 1}, nil)
	if err != nil || out.PagesProcessed != 1 || len(out.Pages) != 1 || !strings.Contains(out.Pages[0].Markdown, "4217") {
		t.Fatal("the capsule's OCR failed", err, out.PagesProcessed)
	}
	u := l.usage(t)
	if l.state(t, "live-o") != "settled" || u.SettledPages != 1 || u.EstimatedCostMicro != 2000 || l.sent.Load() != 1 {
		t.Fatalf("usage %+v, %d requests", u, l.sent.Load())
	}
}

// liveSpeech is AGENTCAPSULE_TEST_TRANSCRIBE_AUDIO, of the duration
// AGENTCAPSULE_TEST_TRANSCRIBE_SECONDS, or a 3-second tone.
func liveSpeech(t *testing.T) llmgateway.TranscribeRequest {
	t.Helper()
	if path := os.Getenv("AGENTCAPSULE_TEST_TRANSCRIBE_AUDIO"); path != "" {
		audio, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		seconds, err := strconv.Atoi(os.Getenv("AGENTCAPSULE_TEST_TRANSCRIBE_SECONDS"))
		if err != nil {
			t.Fatal("AGENTCAPSULE_TEST_TRANSCRIBE_SECONDS gives the recording's duration", err)
		}
		return llmgateway.TranscribeRequest{Audio: audio, Format: strings.TrimPrefix(filepath.Ext(path), "."), DurationSeconds: seconds}
	}
	const rate = 16000
	le := binary.LittleEndian
	samples := []byte{}
	for i := 0; i < 3*rate; i++ {
		samples = le.AppendUint16(samples, uint16(int16(8000*math.Sin(2*math.Pi*440*float64(i)/rate))))
	}
	b := le.AppendUint32([]byte("RIFF"), uint32(36+len(samples)))
	b = le.AppendUint32(append(b, "WAVEfmt "...), 16)
	b = le.AppendUint16(le.AppendUint16(b, 1), 1)
	b = le.AppendUint32(le.AppendUint32(b, rate), 2*rate)
	b = le.AppendUint16(le.AppendUint16(b, 2), 16)
	b = le.AppendUint32(append(b, "data"...), uint32(len(samples)))
	return llmgateway.TranscribeRequest{Audio: append(b, samples...), Format: "wav", DurationSeconds: 3}
}

// livePDF is a one-page PDF that prints "Agent Capsule OCR 4217".
func livePDF() []byte {
	content := "BT /F1 36 Tf 72 700 Td (Agent Capsule OCR 4217) Tj ET"
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content), "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
	b := []byte("%PDF-1.4\n")
	offsets := []int{}
	for i, o := range objects {
		offsets = append(offsets, len(b))
		b = fmt.Appendf(b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := len(b)
	b = fmt.Appendf(b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, o := range offsets {
		b = fmt.Appendf(b, "%010d 00000 n \n", o)
	}
	return fmt.Appendf(b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
}
