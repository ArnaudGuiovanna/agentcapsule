package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func mediaFault(key string) error {
	switch key {
	case "unsupported":
		return &PlatformError{Code: "unsupported"}
	case "unknown":
		return &PlatformError{Code: "outcome_unknown"}
	case "leak":
		return errors.New("sk-live-provider-secret")
	case "feature":
		return &PlatformError{Code: "feature_denied"}
	case "busy":
		return &PlatformError{Code: "concurrency_limited"}
	}
	return nil
}

func (a *platformFake) EmbedLLM(_ context.Context, key string, in LLMEmbed) (LLMEmbedResult, error) {
	a.calls.Add(1)
	if err := mediaFault(key); err != nil {
		return LLMEmbedResult{}, err
	}
	out := LLMEmbedResult{Dimensions: 1, InputTokens: int64(len(in.Input))}
	for range in.Input {
		out.Embeddings = append(out.Embeddings, []byte{0, 0, 0x80, 0x3f}) // 1.0
	}
	if key == "short" {
		out.Embeddings = out.Embeddings[1:]
	}
	return out, nil
}

func (a *platformFake) TranscribeLLM(_ context.Context, key string, in LLMTranscribe) (LLMTranscribeResult, error) {
	a.calls.Add(1)
	if err := mediaFault(key); err != nil {
		return LLMTranscribeResult{}, err
	}
	return LLMTranscribeResult{Text: "heard " + string(in.Audio), Segments: []LLMSegment{{Start: 0, End: 1.5, Text: in.Language}}, DurationSeconds: int64(in.DurationSeconds)}, nil
}

func (a *platformFake) OCRLLM(_ context.Context, key string, in LLMOCR) (LLMOCRResult, error) {
	a.calls.Add(1)
	if err := mediaFault(key); err != nil {
		return LLMOCRResult{}, err
	}
	return LLMOCRResult{Pages: []LLMOCRPage{{Index: 0, Markdown: "# " + in.MediaType}}, PagesProcessed: int64(in.Pages)}, nil
}

var (
	mediaEmbed      = LLMEmbed{Alias: "embed", Input: []string{"one", "two"}}
	mediaTranscribe = LLMTranscribe{Alias: "voice", Audio: []byte("bonjour"), Format: "mp3", DurationSeconds: 3, Language: "fr", Prompt: "greeting"}
	mediaOCR        = LLMOCR{Alias: "ocr", Document: []byte("%PDF"), MediaType: "application/pdf", Pages: 2}
)

// Embeddings, transcription and OCR cross the channel as typed requests under
// the alias the guest named; the host's outcome codes come back, unsupported
// included, and nothing else.
func TestLLMMediaRoutesCarryTypedRequestsAndOutcomes(t *testing.T) {
	c, host, _, api, _ := platformFixture(t)
	e, err := c.EmbedLLM(t.Context(), "e1", mediaEmbed)
	if err != nil || len(e.Embeddings) != 2 || !bytes.Equal(e.Embeddings[1], []byte{0, 0, 0x80, 0x3f}) || e.InputTokens != 2 {
		t.Fatal(e, err)
	}
	tr, err := c.TranscribeLLM(t.Context(), "t1", mediaTranscribe)
	if err != nil || tr.Text != "heard bonjour" || tr.DurationSeconds != 3 || tr.Segments[0].Text != "fr" {
		t.Fatal(tr, err)
	}
	o, err := c.OCRLLM(t.Context(), "o1", mediaOCR)
	if err != nil || o.PagesProcessed != 2 || o.Pages[0].Markdown != "# application/pdf" {
		t.Fatal(o, err)
	}
	for key, code := range map[string]string{"unsupported": "unsupported", "unknown": "outcome_unknown", "leak": "unavailable",
		"feature": "feature_denied", "busy": "concurrency_limited"} {
		_, err1 := c.EmbedLLM(t.Context(), key, mediaEmbed)
		_, err2 := c.TranscribeLLM(t.Context(), key, mediaTranscribe)
		_, err3 := c.OCRLLM(t.Context(), key, mediaOCR)
		for _, err := range []error{err1, err2, err3} {
			var pe *PlatformError
			if !errors.As(err, &pe) || pe.Code != code || strings.Contains(err.Error(), "sk-live") {
				t.Fatal(key, err)
			}
		}
	}
	if _, err = c.EmbedLLM(t.Context(), "short", mediaEmbed); !errors.Is(err, ErrProtocol) {
		t.Fatal("a vector short of the inputs accepted", err)
	}
	calls := api.calls.Load()
	tooMany := LLMEmbed{Alias: "embed", Input: make([]string, MaxLLMEmbedInputs+1)}
	for i := range tooMany.Input {
		tooMany.Input[i] = "x"
	}
	for i, bad := range []LLMEmbed{{Alias: "embed"}, {Alias: "", Input: []string{"x"}}, {Alias: "embed", Input: []string{""}}, tooMany,
		{Alias: "embed", Input: []string{strings.Repeat("a", MaxLLMEmbedInputBytes+1)}}} {
		if _, err = c.EmbedLLM(t.Context(), "bad", bad); err == nil {
			t.Fatal("invalid embedding request accepted", i)
		}
	}
	for i, alter := range []func(*LLMTranscribe){
		func(r *LLMTranscribe) { r.Format = "aac" }, func(r *LLMTranscribe) { r.Audio = nil },
		func(r *LLMTranscribe) { r.Audio = make([]byte, MaxLLMMediaBytes+1) }, func(r *LLMTranscribe) { r.DurationSeconds = 0 },
		func(r *LLMTranscribe) { r.DurationSeconds = MaxLLMAudioSeconds + 1 }, func(r *LLMTranscribe) { r.Language = "FR" },
		func(r *LLMTranscribe) { r.Prompt = strings.Repeat("x", MaxLLMPromptRunes+1) },
	} {
		bad := mediaTranscribe
		alter(&bad)
		if _, err = c.TranscribeLLM(t.Context(), "bad", bad); err == nil {
			t.Fatal("invalid transcription accepted", i)
		}
	}
	for i, alter := range []func(*LLMOCR){
		func(r *LLMOCR) { r.MediaType = "image/gif" }, func(r *LLMOCR) { r.Document = nil },
		func(r *LLMOCR) { r.Document = make([]byte, MaxLLMMediaBytes+1) }, func(r *LLMOCR) { r.Pages = 0 },
		func(r *LLMOCR) { r.Pages = MaxLLMOCRPages + 1 },
	} {
		bad := mediaOCR
		alter(&bad)
		if _, err = c.OCRLLM(t.Context(), "bad", bad); err == nil {
			t.Fatal("invalid OCR request accepted", i)
		}
	}
	// The same checks hold on the host for a client that skips them, and a
	// request rides only on its own route.
	badOCR := mediaOCR
	badOCR.Pages = 9
	for i, bad := range []struct {
		path string
		in   *platformRequest
	}{
		{"/v1/llm/ocr", &platformRequest{Key: "x", OCR: &badOCR}},
		{"/v1/llm/embed", &platformRequest{Key: "", Embed: &mediaEmbed}},
		{"/v1/llm/embed", &platformRequest{Key: strings.Repeat("k", 201), Embed: &mediaEmbed}},
		{"/v1/llm/embed", &platformRequest{Key: "x"}},
		{"/v1/llm/transcribe", &platformRequest{Key: "x", Embed: &mediaEmbed}},
		{"/v1/llm/transcribe", &platformRequest{Key: "x", Transcribe: &mediaTranscribe, OCR: &mediaOCR}},
		{"/v1/llm/ocr", &platformRequest{Key: "x", OCR: &mediaOCR, LLM: &LLMRequest{Alias: "a", Messages: []LLMMessage{{Role: "user", Content: "x"}}}}},
		{"/v1/directory/search", &platformRequest{Embed: &mediaEmbed}},
		{"/v1/llm/complete", &platformRequest{Key: "x", LLM: &LLMRequest{Alias: "a", Messages: []LLMMessage{{Role: "user", Content: "x"}}}, OCR: &mediaOCR}},
	} {
		var pe *PlatformError
		if _, err = c.callWithTimeout(t.Context(), bad.path, bad.in, 0); !errors.As(err, &pe) || pe.Code != "invalid" {
			t.Fatal("host accepted an invalid media request", i, err)
		}
	}
	if api.calls.Load() != calls {
		t.Fatal("an invalid media request reached the adapter")
	}
	// The payload names no tenant, provider or credential, and the refusal of
	// an undeclared operation is a client error.
	for path, status := range map[string]int{"/v1/llm/embed": 400, "/v1/llm/ocr": 400} {
		in := platformRequest{Protocol: Version, Identity: host.Identity, Key: "unsupported", Embed: &mediaEmbed}
		if path == "/v1/llm/ocr" {
			in = platformRequest{Protocol: Version, Identity: host.Identity, Key: "forged", OCR: &mediaOCR}
		}
		b, _ := json.Marshal(in)
		if path == "/v1/llm/ocr" {
			b = bytes.Replace(b, []byte(`"alias":`), []byte(`"provider_secret":"x","alias":`), 1)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+c.client.serverName+path, bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.client.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Fatal(path, resp.StatusCode)
		}
	}
	if api.calls.Load() != calls+1 {
		t.Fatal("an unknown field reached the adapter", api.calls.Load()-calls)
	}
}

// bareHost offers none of the optional platform routes.
type bareHost struct{}

func (bareHost) Validate(context.Context) error { return nil }
func (bareHost) Submit(context.Context, string, Submission) (PlatformReceipt, error) {
	return PlatformReceipt{}, nil
}
func (bareHost) Reply(context.Context, string, string, Reply) (PlatformReceipt, error) {
	return PlatformReceipt{}, nil
}
func (bareHost) Search(context.Context, []string) ([]string, error) { return nil, nil }

func TestLLMMediaRoutesAreUnavailableWithoutTheBridge(t *testing.T) {
	c, _, _, _ := platformFixtureFor(t, bareHost{})
	var pe *PlatformError
	if _, err := c.TranscribeLLM(t.Context(), "k", mediaTranscribe); !errors.As(err, &pe) || pe.Code != "unavailable" {
		t.Fatal(err)
	}
}

func TestLLMMediaRoutesNeedLLMInvoke(t *testing.T) {
	api := &gatedPlatform{allowed: []string{"agents.delegate"}}
	c, _, _, _ := platformFixtureFor(t, api)
	var denied *PlatformError
	_, err1 := c.EmbedLLM(t.Context(), "k", mediaEmbed)
	_, err2 := c.TranscribeLLM(t.Context(), "k", mediaTranscribe)
	_, err3 := c.OCRLLM(t.Context(), "k", mediaOCR)
	for _, err := range []error{err1, err2, err3} {
		if !errors.As(err, &denied) || denied.Code != "capability_denied" || api.calls.Load() != 0 {
			t.Fatal("a media call without llm.invoke", err, api.calls.Load())
		}
	}
	api.mu.Lock()
	api.allowed = append(api.allowed, "llm.invoke")
	api.mu.Unlock()
	if _, err := c.OCRLLM(t.Context(), "k", mediaOCR); err != nil || api.calls.Load() != 1 {
		t.Fatal(err)
	}
}
