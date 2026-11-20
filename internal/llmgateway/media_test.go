package llmgateway

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// provider is a fake upstream: it records each request and answers with
// reply, or with status when it is not 200.
type provider struct {
	*httptest.Server
	calls       atomic.Int32
	path, ctype string
	body        []byte
	form        map[string][]string
	file        []byte
	fileName    string
	fileType    string
}

func newProvider(t *testing.T, status int, reply string) *provider {
	t.Helper()
	p := &provider{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		p.path, p.ctype = r.URL.Path, r.Header.Get("Content-Type")
		if strings.HasPrefix(p.ctype, "multipart/form-data") {
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				t.Error("multipart body", err)
			} else {
				p.form = r.MultipartForm.Value
				for _, fh := range r.MultipartForm.File["file"] {
					f, _ := fh.Open()
					p.file, _ = io.ReadAll(f)
					f.Close()
					p.fileName, p.fileType = fh.Filename, fh.Header.Get("Content-Type")
				}
			}
		} else {
			p.body, _ = io.ReadAll(r.Body)
		}
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *provider) route() Route {
	return Route{Kind: "openai_compatible", BaseURL: p.URL + "/v1", UpstreamModel: "m1", Secret: "sk-media-test", Key: "t/media"} // gitleaks:allow test fixture, not a credential
}

func floats(v ...float32) []byte {
	b := []byte{}
	for _, f := range v {
		b = binary.LittleEndian.AppendUint32(b, math.Float32bits(f))
	}
	return b
}

func TestEmbedAsksForBase64AndKeepsTheInputOrder(t *testing.T) {
	first, second := base64.StdEncoding.EncodeToString(floats(1, 2)), base64.StdEncoding.EncodeToString(floats(3, 4))
	p := newProvider(t, 200, `{"data":[{"index":1,"embedding":"`+second+`"},{"index":0,"embedding":"`+first+`"}],"usage":{"prompt_tokens":9,"total_tokens":9}}`)
	out, err := fast(Config{}).Embed(t.Context(), p.route(), EmbedRequest{Input: []string{"one", "two"}})
	if err != nil || out.Dimensions != 2 || out.Usage.InputTokens != 9 || !bytes.Equal(out.Embeddings[0], floats(1, 2)) || !bytes.Equal(out.Embeddings[1], floats(3, 4)) {
		t.Fatal(out, err)
	}
	var sent map[string]any
	if p.path != "/v1/embeddings" || json.Unmarshal(p.body, &sent) != nil || sent["model"] != "m1" || sent["encoding_format"] != "base64" || len(sent["input"].([]any)) != 2 {
		t.Fatal(p.path, string(p.body))
	}
	// A provider that ignores base64 sends numbers: the same bytes come back.
	p = newProvider(t, 200, `{"data":[{"index":0,"embedding":[1,2]}],"usage":{"prompt_tokens":2}}`)
	if out, err = fast(Config{}).Embed(t.Context(), p.route(), EmbedRequest{Input: []string{"one"}}); err != nil || !bytes.Equal(out.Embeddings[0], floats(1, 2)) {
		t.Fatal(out, err)
	}
	// No usage reported: the caller settles on its reservation.
	p = newProvider(t, 200, `{"data":[{"embedding":[1]}]}`)
	if out, err = fast(Config{}).Embed(t.Context(), p.route(), EmbedRequest{Input: []string{"one"}}); err != nil || out.Usage.InputTokens != 0 || out.Dimensions != 1 {
		t.Fatal(out, err)
	}
}

func TestEmbedAnswerThatCannotBeAccountedIsOutcomeUnknown(t *testing.T) {
	big := base64.StdEncoding.EncodeToString(make([]byte, 16<<10))
	for name, reply := range map[string]string{
		"missing vector":       `{"data":[{"index":0,"embedding":"` + base64.StdEncoding.EncodeToString(floats(1)) + `"}]}`,
		"repeated index":       `{"data":[{"index":0,"embedding":[1]},{"index":0,"embedding":[2]}]}`,
		"mixed dimensions":     `{"data":[{"index":0,"embedding":[1]},{"index":1,"embedding":[2,3]}]}`,
		"not float32":          `{"data":[{"index":0,"embedding":"AAA="},{"index":1,"embedding":"AAA="}]}`,
		"past the channel":     `{"data":[` + strings.Repeat(`{"embedding":"`+big+`"},`, 63) + `{"embedding":"` + big + `"}]}`,
		"negative usage":       `{"data":[{"embedding":[1]},{"embedding":[2]}],"usage":{"prompt_tokens":-1}}`,
		"not an answer at all": `<html>`,
	} {
		n := 2
		if name == "past the channel" {
			n = 64
		}
		input := make([]string, n)
		for i := range input {
			input[i] = "x"
		}
		p := newProvider(t, 200, reply)
		if _, err := fast(Config{MaxResponse: 8 << 20}).Embed(t.Context(), p.route(), EmbedRequest{Input: input}); !errors.Is(err, ErrOutcomeUnknown) || p.calls.Load() != 1 {
			t.Fatal(name, err, p.calls.Load())
		}
	}
}

func TestMediaRequestsRefusedBeforeAnythingIsSent(t *testing.T) {
	p := newProvider(t, 200, `{}`)
	g := fast(Config{})
	anthropic := p.route()
	anthropic.Kind = "anthropic"
	if _, err := g.Embed(t.Context(), anthropic, EmbedRequest{Input: []string{"x"}}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("embeddings sent to an anthropic provider", err)
	}
	if _, err := g.Transcribe(t.Context(), anthropic, TranscribeRequest{Audio: []byte("a"), Format: "mp3", DurationSeconds: 1}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := g.OCR(t.Context(), anthropic, OCRRequest{Document: []byte("a"), MediaType: "image/png", Pages: 1}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	r := p.route()
	tooMany := make([]string, MaxEmbedInputs+1)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	for i, q := range []EmbedRequest{{}, {Input: tooMany}, {Input: []string{""}}, {Input: []string{strings.Repeat("a", MaxEmbedInputBytes+1)}},
		{Input: []string{"\xff"}}, {Input: strings.Split(strings.Repeat(strings.Repeat("a", MaxEmbedInputBytes)+",", 31), ",")[:31]}} {
		if _, err := g.Embed(t.Context(), r, q); !errors.Is(err, ErrInvalid) {
			t.Fatal("embed", i, err)
		}
	}
	audio := []byte("audio")
	for i, q := range []TranscribeRequest{{Audio: audio, Format: "aac", DurationSeconds: 1}, {Format: "mp3", DurationSeconds: 1},
		{Audio: make([]byte, MaxMediaBytes+1), Format: "mp3", DurationSeconds: 1}, {Audio: audio, Format: "mp3"},
		{Audio: audio, Format: "mp3", DurationSeconds: MaxAudioSeconds + 1}, {Audio: audio, Format: "mp3", DurationSeconds: 1, Language: "fra"},
		{Audio: audio, Format: "mp3", DurationSeconds: 1, Prompt: strings.Repeat("é", MaxPromptRunes+1)}} {
		if _, err := g.Transcribe(t.Context(), r, q); !errors.Is(err, ErrInvalid) {
			t.Fatal("transcribe", i, err)
		}
	}
	for i, q := range []OCRRequest{{Document: audio, MediaType: "image/gif", Pages: 1}, {MediaType: "image/png", Pages: 1},
		{Document: make([]byte, MaxMediaBytes+1), MediaType: "application/pdf", Pages: 1}, {Document: audio, MediaType: "application/pdf"},
		{Document: audio, MediaType: "application/pdf", Pages: MaxOCRPages + 1}} {
		if _, err := g.OCR(t.Context(), r, q); !errors.Is(err, ErrInvalid) {
			t.Fatal("ocr", i, err)
		}
	}
	if p.calls.Load() != 0 {
		t.Fatal("a refused request reached the provider", p.calls.Load())
	}
}

func TestTranscribeBuildsTheMultipartBodyAndReadsTheDuration(t *testing.T) {
	p := newProvider(t, 200, `{"task":"transcribe","language":"french","duration":287.2,"text":"Bonjour.",
		"segments":[{"id":0,"start":0.0,"end":4.2,"text":"Bonjour.","tokens":[1,2],"avg_logprob":-0.2}]}`)
	audio := []byte("ID3 fake mp3 bytes \x00\xff")
	out, err := fast(Config{}).Transcribe(t.Context(), p.route(), TranscribeRequest{Audio: audio, Format: "mp3", DurationSeconds: 290, Language: "fr", Prompt: "Finance"})
	if err != nil || out.Text != "Bonjour." || out.DurationSeconds != 288 || len(out.Segments) != 1 || out.Segments[0] != (Segment{Start: 0, End: 4.2, Text: "Bonjour."}) {
		t.Fatal(out, err)
	}
	want := map[string]string{"model": "m1", "response_format": "verbose_json", "timestamp_granularities[]": "segment", "language": "fr", "prompt": "Finance"}
	for k, v := range want {
		if got := p.form[k]; len(got) != 1 || got[0] != v {
			t.Fatal(k, got)
		}
	}
	if p.path != "/v1/audio/transcriptions" || !bytes.Equal(p.file, audio) || p.fileName != "audio.mp3" || p.fileType != "audio/mpeg" {
		t.Fatal(p.path, p.fileName, p.fileType, len(p.file))
	}
	// Mistral reports the seconds in its usage; a provider may report none.
	for reply, seconds := range map[string]int64{
		`{"text":"x","usage":{"prompt_audio_seconds":61}}`:     61,
		`{"text":"x","usage":{"type":"duration","seconds":3}}`: 3,
		`{"text":""}`: 0,
	} {
		p = newProvider(t, 200, reply)
		out, err = fast(Config{}).Transcribe(t.Context(), p.route(), TranscribeRequest{Audio: audio, Format: "wav", DurationSeconds: 5})
		if err != nil || out.DurationSeconds != seconds || out.Segments == nil {
			t.Fatal(reply, out, err)
		}
		if _, ok := p.form["language"]; ok {
			t.Fatal("an empty language was sent")
		}
	}
	for _, reply := range []string{`{"duration":3}`, `{"text":"x","duration":-1}`, `{"text":"x","segments":[{"start":5,"end":1}]}`} {
		p = newProvider(t, 200, reply)
		if _, err = fast(Config{}).Transcribe(t.Context(), p.route(), TranscribeRequest{Audio: audio, Format: "wav", DurationSeconds: 5}); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal(reply, err)
		}
	}
}

// A transcription cut after it was sent may have been billed: it is never
// retried and its outcome is unknown.
func TestTranscribeCutAfterSendingIsOutcomeUnknownAndNotRetried(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.ReadAll(r.Body)
		<-release
	}))
	defer srv.Close()
	defer close(release)
	route := Route{Kind: "openai_compatible", BaseURL: srv.URL, UpstreamModel: "m", Secret: "s-transcribe", Key: "t/cut"} // gitleaks:allow test fixture, not a credential
	_, err := fast(Config{Timeout: 50 * time.Millisecond, MaxAttempts: 3}).Transcribe(t.Context(), route, TranscribeRequest{Audio: []byte("a"), Format: "ogg", DurationSeconds: 1})
	if !errors.Is(err, ErrOutcomeUnknown) || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
}

func TestOCRSendsADataURLAndOnlyTheDeclaredPages(t *testing.T) {
	p := newProvider(t, 200, `{"pages":[{"index":0,"markdown":"# Title","images":[],"dimensions":{"dpi":200}},{"index":1,"markdown":"text"}],
		"model":"mistral-ocr","usage_info":{"pages_processed":2,"doc_size_bytes":42}}`)
	pdf := []byte("%PDF-1.4 fake")
	out, err := fast(Config{}).OCR(t.Context(), p.route(), OCRRequest{Document: pdf, MediaType: "application/pdf", Pages: 2})
	if err != nil || out.PagesProcessed != 2 || len(out.Pages) != 2 || out.Pages[0] != (OCRPage{Index: 0, Markdown: "# Title"}) {
		t.Fatal(out, err)
	}
	var sent struct {
		Model    string            `json:"model"`
		Document map[string]string `json:"document"`
		Pages    []int             `json:"pages"`
		Images   bool              `json:"include_image_base64"`
	}
	if p.path != "/v1/ocr" || json.Unmarshal(p.body, &sent) != nil || sent.Model != "m1" || sent.Document["type"] != "document_url" ||
		sent.Document["document_url"] != "data:application/pdf;base64,"+base64.StdEncoding.EncodeToString(pdf) || len(sent.Pages) != 2 || sent.Pages[1] != 1 || sent.Images {
		t.Fatal(p.path, string(p.body))
	}
	// An image is one page, sent as an image URL.
	p = newProvider(t, 200, `{"pages":[{"index":0,"markdown":"x"}]}`)
	if out, err = fast(Config{}).OCR(t.Context(), p.route(), OCRRequest{Document: []byte("png"), MediaType: "image/png", Pages: 1}); err != nil || out.PagesProcessed != 0 {
		t.Fatal(out, err)
	}
	sent.Pages = nil
	if json.Unmarshal(p.body, &sent) != nil || sent.Document["type"] != "image_url" || !strings.HasPrefix(sent.Document["image_url"], "data:image/png;base64,") || sent.Pages != nil {
		t.Fatal(string(p.body))
	}
	for _, reply := range []string{`{}`, `{"pages":[{"markdown":"x"}]}`, `{"pages":[],"usage_info":{"pages_processed":-1}}`} {
		p = newProvider(t, 200, reply)
		if _, err = fast(Config{}).OCR(t.Context(), p.route(), OCRRequest{Document: pdf, MediaType: "application/pdf", Pages: 1}); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal(reply, err)
		}
	}
	// A provider refusal is definite and not retried; a 429 is retried.
	p = newProvider(t, 422, "")
	if _, err = fast(Config{MaxAttempts: 3}).OCR(t.Context(), p.route(), OCRRequest{Document: pdf, MediaType: "application/pdf", Pages: 1}); !errors.Is(err, ErrRejected) || p.calls.Load() != 1 {
		t.Fatal(err, p.calls.Load())
	}
	p = newProvider(t, 429, "")
	if _, err = fast(Config{MaxAttempts: 2}).OCR(t.Context(), p.route(), OCRRequest{Document: pdf, MediaType: "application/pdf", Pages: 1}); !errors.Is(err, ErrRateLimited) || p.calls.Load() != 2 {
		t.Fatal(err, p.calls.Load())
	}
}
