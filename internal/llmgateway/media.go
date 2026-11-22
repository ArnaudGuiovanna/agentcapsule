package llmgateway

import (
	"errors"
	"unicode/utf8"
)

// Bounds of the multimodal routes: embeddings, transcription and OCR
// (ADR 023 §12). A request and its answer cross the VM's platform channel
// inside its 1 MiB message, so each is bounded by MaxForwardBytes. The host
// never decodes the media: it checks the size of the bytes, and the duration
// and page count are the caller's declarations, bounded here.
const (
	MaxMediaBytes      = 700 << 10 // decoded audio or document
	MaxEmbedInputs     = 64
	MaxEmbedInputBytes = 32 << 10
	MaxAudioSeconds    = 600
	MaxOCRPages        = 8
	MaxPromptRunes     = 1024
)

// ErrUnsupported: the alias's provider kind does not serve this operation
// (only an openai_compatible provider serves embeddings, transcription and
// OCR). The alias's operations are checked before this, when it is set.
var ErrUnsupported = errors.New("llm provider does not serve this operation")

// AudioFormats maps the accepted audio formats to their media types.
var AudioFormats = map[string]string{"mp3": "audio/mpeg", "wav": "audio/wav", "flac": "audio/flac", "ogg": "audio/ogg", "m4a": "audio/mp4", "webm": "audio/webm"}

// DocumentTypes are the media types OCR accepts.
var DocumentTypes = map[string]bool{"image/png": true, "image/jpeg": true, "image/webp": true, "application/pdf": true}

// EmbedRequest asks for one vector per input string.
type EmbedRequest struct {
	Input []string
}

// EmbedResponse holds one little-endian float32 vector per input, in the
// order of the input. Usage.InputTokens is what the provider reported, 0 when
// it reported none.
type EmbedResponse struct {
	Embeddings [][]byte
	Dimensions int
	Usage      Usage
}

// Valid applies the route's bounds.
func (q EmbedRequest) Valid() bool {
	if len(q.Input) < 1 || len(q.Input) > MaxEmbedInputs {
		return false
	}
	total := 0
	for _, s := range q.Input {
		if s == "" || len(s) > MaxEmbedInputBytes || !utf8.ValidString(s) {
			return false
		}
		total += len(s)
	}
	return total <= MaxForwardBytes
}

// ReservedTokens is the reservation of an embedding call: the estimate of
// its inputs, as for a completion (EstimateTokens).
func (q EmbedRequest) ReservedTokens() int64 {
	var c tokenCount
	for _, s := range q.Input {
		c.add(s)
	}
	return c.estimate()
}

// TranscribeRequest is one audio segment and its declared duration.
type TranscribeRequest struct {
	Audio           []byte
	Format          string
	DurationSeconds int
	Language        string // ISO 639-1, optional
	Prompt          string // optional
}

// Segment is a part of a transcript with its time stamps, in seconds.
type Segment struct {
	Start, End float64
	Text       string
}

// TranscribeResponse is the transcript. DurationSeconds is the duration the
// provider reported, rounded up to the second, 0 when it reported none.
type TranscribeResponse struct {
	Text            string
	Segments        []Segment
	DurationSeconds int64
}

func validLanguage(s string) bool {
	return s == "" || len(s) == 2 && s[0] >= 'a' && s[0] <= 'z' && s[1] >= 'a' && s[1] <= 'z'
}

// Valid applies the route's bounds.
func (q TranscribeRequest) Valid() bool {
	_, format := AudioFormats[q.Format]
	return format && len(q.Audio) >= 1 && len(q.Audio) <= MaxMediaBytes && q.DurationSeconds >= 1 && q.DurationSeconds <= MaxAudioSeconds &&
		validLanguage(q.Language) && utf8.ValidString(q.Prompt) && utf8.RuneCountInString(q.Prompt) <= MaxPromptRunes
}

// OCRRequest is one image or PDF and its declared page count.
type OCRRequest struct {
	Document  []byte
	MediaType string
	Pages     int
}

// OCRPage is one recognized page, as Markdown.
type OCRPage struct {
	Index    int
	Markdown string
}

// OCRResponse is the recognized pages. PagesProcessed is what the provider
// reported, 0 when it reported none.
type OCRResponse struct {
	Pages          []OCRPage
	PagesProcessed int64
}

// Valid applies the route's bounds.
func (q OCRRequest) Valid() bool {
	return DocumentTypes[q.MediaType] && len(q.Document) >= 1 && len(q.Document) <= MaxMediaBytes && q.Pages >= 1 && q.Pages <= MaxOCRPages
}
