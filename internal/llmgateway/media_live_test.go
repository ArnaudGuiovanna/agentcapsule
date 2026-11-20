//go:build llmlive

package llmgateway

// Live checks of the multimodal routes against real providers (ADR 023 §12).
// Each needs its own variables and runs only with -tags llmlive:
//
//   - embeddings: AGENTCAPSULE_TEST_LLM_BASE_URL and
//     AGENTCAPSULE_TEST_EMBED_MODEL, normally a local Ollama with a small
//     embedding model (all-minilm);
//   - transcription: AGENTCAPSULE_TEST_TRANSCRIBE_BASE_URL,
//     AGENTCAPSULE_TEST_TRANSCRIBE_MODEL and AGENTCAPSULE_TEST_TRANSCRIBE_SECRET,
//     a hosted OpenAI-compatible provider; AGENTCAPSULE_TEST_TRANSCRIBE_AUDIO
//     may name a speech recording (at most 700 KiB) and
//     AGENTCAPSULE_TEST_TRANSCRIBE_SECONDS its duration, otherwise a generated
//     3-second tone is sent;
//   - OCR: AGENTCAPSULE_TEST_OCR_BASE_URL, AGENTCAPSULE_TEST_OCR_MODEL and
//     AGENTCAPSULE_TEST_OCR_SECRET, Mistral's API.
//
// A secret is never logged. Model output is not asserted beyond the
// contract, except the OCR of a known line.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// liveMediaRoute reads a route from AGENTCAPSULE_TEST_<NAME>_BASE_URL, _MODEL
// and _SECRET (a missing secret: no authentication).
func liveMediaRoute(t *testing.T, name, base, model string) Route {
	t.Helper()
	if base == "" || model == "" {
		t.Fatalf("-tags llmlive needs the %s provider's base URL and model", name)
	}
	secret := os.Getenv("AGENTCAPSULE_TEST_" + strings.ToUpper(name) + "_SECRET")
	if name == "embed" {
		secret = os.Getenv("AGENTCAPSULE_TEST_LLM_SECRET")
	}
	mode := "secret"
	if secret == "" {
		mode = "none"
	}
	return Route{AuthMode: mode, Kind: "openai_compatible", BaseURL: base, UpstreamModel: model, Secret: secret, Key: "live/" + name}
}

func liveEmbedRoute(t *testing.T) Route {
	return liveMediaRoute(t, "embed", os.Getenv("AGENTCAPSULE_TEST_LLM_BASE_URL"), os.Getenv("AGENTCAPSULE_TEST_EMBED_MODEL"))
}

func liveTranscribeRoute(t *testing.T) Route {
	return liveMediaRoute(t, "transcribe", os.Getenv("AGENTCAPSULE_TEST_TRANSCRIBE_BASE_URL"), os.Getenv("AGENTCAPSULE_TEST_TRANSCRIBE_MODEL"))
}

func liveOCRRoute(t *testing.T) Route {
	return liveMediaRoute(t, "ocr", os.Getenv("AGENTCAPSULE_TEST_OCR_BASE_URL"), os.Getenv("AGENTCAPSULE_TEST_OCR_MODEL"))
}

// liveSpeech is the audio a live transcription sends, and its declared
// duration.
func liveSpeech(t *testing.T) TranscribeRequest {
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
		return TranscribeRequest{Audio: audio, Format: strings.TrimPrefix(filepath.Ext(path), "."), DurationSeconds: seconds}
	}
	return TranscribeRequest{Audio: toneWAV(3), Format: "wav", DurationSeconds: 3}
}

// toneWAV is seconds of a 440 Hz tone, 16 kHz mono 16-bit PCM.
func toneWAV(seconds int) []byte {
	const rate = 16000
	samples := make([]byte, 0, 2*rate*seconds)
	for i := 0; i < rate*seconds; i++ {
		v := int16(8000 * math.Sin(2*math.Pi*440*float64(i)/rate))
		samples = binary.LittleEndian.AppendUint16(samples, uint16(v))
	}
	le := binary.LittleEndian
	b := le.AppendUint32([]byte("RIFF"), uint32(36+len(samples)))
	b = append(b, "WAVEfmt "...)
	b = le.AppendUint32(b, 16)     // fmt chunk size
	b = le.AppendUint16(b, 1)      // PCM
	b = le.AppendUint16(b, 1)      // mono
	b = le.AppendUint32(b, rate)   // samples per second
	b = le.AppendUint32(b, 2*rate) // bytes per second
	b = le.AppendUint16(b, 2)      // block align
	b = le.AppendUint16(b, 16)     // bits per sample
	b = le.AppendUint32(append(b, "data"...), uint32(len(samples)))
	return append(b, samples...)
}

// liveOCRText is the line livePDF prints.
const liveOCRText = "Agent Capsule OCR 4217"

// livePDF is a one-page PDF that prints liveOCRText in Helvetica.
func livePDF() []byte {
	content := "BT /F1 36 Tf 72 700 Td (" + liveOCRText + ") Tj ET"
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := []int{}
	for i, o := range objects {
		offsets = append(offsets, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, o := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return b.Bytes()
}

func TestEmbedLiveProviderReturnsVectorsAndUsage(t *testing.T) {
	g := live(Config{Timeout: 2 * time.Minute, MaxAttempts: 1})
	out, err := g.Embed(t.Context(), liveEmbedRoute(t), EmbedRequest{Input: []string{"What is the net present value?", "Discount the cash flows."}})
	if err != nil {
		t.Fatal("live embedding failed", err)
	}
	if len(out.Embeddings) != 2 || out.Dimensions < 1 || len(out.Embeddings[0]) != 4*out.Dimensions || bytes.Equal(out.Embeddings[0], out.Embeddings[1]) {
		t.Fatalf("vectors: %d of %d dimensions", len(out.Embeddings), out.Dimensions)
	}
	if out.Usage.InputTokens <= 0 {
		t.Fatal("the provider reported no usage", out.Usage)
	}
	t.Logf("%d vectors of %d dimensions, %d input tokens", len(out.Embeddings), out.Dimensions, out.Usage.InputTokens)
}

func TestTranscribeLiveProviderReturnsATranscriptAndItsDuration(t *testing.T) {
	q := liveSpeech(t)
	out, err := live(Config{Timeout: 2 * time.Minute, MaxAttempts: 1}).Transcribe(t.Context(), liveTranscribeRoute(t), q)
	if err != nil {
		t.Fatal("live transcription failed", err)
	}
	if out.DurationSeconds <= 0 || out.DurationSeconds > int64(q.DurationSeconds)+1 {
		t.Fatal("the provider's duration", out.DurationSeconds, "declared", q.DurationSeconds)
	}
	t.Logf("transcript of %d bytes, %d segments, %d s", len(out.Text), len(out.Segments), out.DurationSeconds)
}

func TestOCRLiveProviderReadsTheDeclaredPage(t *testing.T) {
	out, err := live(Config{Timeout: 2 * time.Minute, MaxAttempts: 1}).OCR(t.Context(), liveOCRRoute(t), OCRRequest{Document: livePDF(), MediaType: "application/pdf", Pages: 1})
	if err != nil {
		t.Fatal("live OCR failed", err)
	}
	if out.PagesProcessed != 1 || len(out.Pages) != 1 || !strings.Contains(out.Pages[0].Markdown, "4217") {
		t.Fatalf("pages processed %d, %d pages", out.PagesProcessed, len(out.Pages))
	}
	t.Logf("%d page, %d bytes of Markdown", out.PagesProcessed, len(out.Pages[0].Markdown))
}
