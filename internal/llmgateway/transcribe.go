package llmgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"mime/multipart"
	"net/textproto"
)

// Transcribe sends one audio segment to an openai_compatible provider (POST
// /audio/transcriptions). The gateway builds the provider's multipart body
// from the caller's fields, with response_format verbose_json and segment time
// stamps; it never decodes the audio. Retries, breaker and outcome rules are
// those of Complete.
func (g *Gateway) Transcribe(ctx context.Context, route Route, q TranscribeRequest) (out TranscribeResponse, err error) {
	ctx, span := startCall(ctx, "transcribe", route)
	defer func() { endCall(span, Usage{}, err) }()
	if !q.Valid() || !route.validAuth() || route.UpstreamModel == "" {
		return TranscribeResponse{}, ErrInvalid
	}
	if route.Kind != "openai_compatible" {
		return TranscribeResponse{}, ErrUnsupported
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	fields := [][2]string{{"model", route.UpstreamModel}, {"response_format", "verbose_json"}, {"timestamp_granularities[]", "segment"}}
	if q.Language != "" {
		fields = append(fields, [2]string{"language", q.Language})
	}
	if q.Prompt != "" {
		fields = append(fields, [2]string{"prompt", q.Prompt})
	}
	for _, f := range fields {
		if err = form.WriteField(f[0], f[1]); err != nil {
			return TranscribeResponse{}, ErrInvalid
		}
	}
	part := textproto.MIMEHeader{}
	part.Set("Content-Disposition", `form-data; name="file"; filename="audio.`+q.Format+`"`)
	part.Set("Content-Type", AudioFormats[q.Format])
	w, err := form.CreatePart(part)
	if err != nil {
		return TranscribeResponse{}, ErrInvalid
	}
	if _, err = w.Write(q.Audio); err != nil {
		return TranscribeResponse{}, ErrInvalid
	}
	if err = form.Close(); err != nil {
		return TranscribeResponse{}, ErrInvalid
	}
	headers := route.headers()
	headers["Content-Type"] = form.FormDataContentType()
	var answer TranscribeResponse
	err = g.exchange(ctx, route.Key, join(route.BaseURL, "/audio/transcriptions"), body.Bytes(), headers, func(raw []byte) (err error) {
		answer, err = parseTranscript(raw)
		return err
	})
	if err != nil {
		return TranscribeResponse{}, err
	}
	return answer, nil
}

// parseTranscript reads a verbose_json transcript. The duration is the
// provider's "duration" (OpenAI), or its usage in seconds ("seconds", or
// Mistral's "prompt_audio_seconds"), rounded up to the second.
func parseTranscript(raw []byte) (TranscribeResponse, error) {
	var v struct {
		Text     *string  `json:"text"`
		Duration *float64 `json:"duration"`
		Segments []struct {
			Start float64 `json:"start"`
			End   float64 `json:"end"`
			Text  string  `json:"text"`
		} `json:"segments"`
		Usage struct {
			Seconds            *float64 `json:"seconds"`
			PromptAudioSeconds *float64 `json:"prompt_audio_seconds"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Text == nil {
		return TranscribeResponse{}, ErrInvalid
	}
	out := TranscribeResponse{Text: *v.Text, Segments: make([]Segment, 0, len(v.Segments))}
	for _, s := range v.Segments {
		if !validSeconds(s.Start) || !validSeconds(s.End) || s.End < s.Start {
			return TranscribeResponse{}, ErrInvalid
		}
		out.Segments = append(out.Segments, Segment{Start: s.Start, End: s.End, Text: s.Text})
	}
	for _, d := range []*float64{v.Duration, v.Usage.Seconds, v.Usage.PromptAudioSeconds} {
		if d == nil {
			continue
		}
		if !validSeconds(*d) {
			return TranscribeResponse{}, ErrInvalid
		}
		out.DurationSeconds = int64(math.Ceil(*d))
		break
	}
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) > MaxForwardBytes {
		return TranscribeResponse{}, ErrInvalid
	}
	return out, nil
}

// validSeconds bounds a time the provider reports: at most a day.
func validSeconds(f float64) bool { return f >= 0 && f <= 86400 && !math.IsNaN(f) }
