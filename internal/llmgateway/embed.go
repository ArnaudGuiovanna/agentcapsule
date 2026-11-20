package llmgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
)

// Embed asks an openai_compatible provider for embeddings (POST /embeddings,
// encoding_format base64), with the retries, breaker and outcome rules of
// Complete. A vector the provider sends as a JSON array of numbers is
// converted to the same little-endian float32 bytes. An answer that cannot be
// read, or whose vectors would not fit the platform channel, was still
// produced: ErrOutcomeUnknown.
func (g *Gateway) Embed(ctx context.Context, route Route, q EmbedRequest) (out EmbedResponse, err error) {
	ctx, span := startCall(ctx, "embed", route)
	defer func() { endCall(span, out.Usage, err) }()
	if !q.Valid() || !route.validAuth() || route.UpstreamModel == "" {
		return EmbedResponse{}, ErrInvalid
	}
	if route.Kind != "openai_compatible" {
		return EmbedResponse{}, ErrUnsupported
	}
	body, err := json.Marshal(map[string]any{"model": route.UpstreamModel, "input": q.Input, "encoding_format": "base64"})
	if err != nil {
		return EmbedResponse{}, ErrInvalid
	}
	var answer EmbedResponse
	err = g.exchange(ctx, route.Key, join(route.BaseURL, "/embeddings"), body, route.headers(), func(raw []byte) (err error) {
		answer, err = parseEmbeddings(raw, len(q.Input))
		return err
	})
	if err != nil {
		return EmbedResponse{}, err
	}
	return answer, nil
}

func parseEmbeddings(raw []byte, n int) (EmbedResponse, error) {
	var v struct {
		Data []struct {
			Embedding json.RawMessage `json:"embedding"`
			Index     *int            `json:"index"`
		} `json:"data"`
		Usage struct {
			Prompt int64 `json:"prompt_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Data) != n || v.Usage.Prompt < 0 {
		return EmbedResponse{}, ErrInvalid
	}
	out := EmbedResponse{Embeddings: make([][]byte, n), Usage: Usage{InputTokens: v.Usage.Prompt}}
	encoded := 0
	for i, d := range v.Data {
		at := i
		if d.Index != nil {
			at = *d.Index
		}
		if at < 0 || at >= n || out.Embeddings[at] != nil {
			return EmbedResponse{}, ErrInvalid
		}
		vec, ok := vectorBytes(d.Embedding)
		if !ok || (out.Dimensions != 0 && len(vec) != 4*out.Dimensions) {
			return EmbedResponse{}, ErrInvalid
		}
		out.Dimensions = len(vec) / 4
		out.Embeddings[at] = vec
		encoded += base64.StdEncoding.EncodedLen(len(vec)) + 3
	}
	if encoded > MaxForwardBytes {
		return EmbedResponse{}, ErrInvalid
	}
	return out, nil
}

// vectorBytes reads a vector sent as base64 of little-endian float32 or as a
// JSON array of numbers.
func vectorBytes(raw json.RawMessage) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, false
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(b) == 0 || len(b)%4 != 0 {
			return nil, false
		}
		for i := 0; i < len(b); i += 4 {
			if f := math.Float32frombits(binary.LittleEndian.Uint32(b[i:])); math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
				return nil, false
			}
		}
		return b, true
	}
	var floats []*float64
	if json.Unmarshal(raw, &floats) != nil || len(floats) == 0 {
		return nil, false
	}
	b := make([]byte, 0, 4*len(floats))
	for _, f := range floats {
		if f == nil || math.Abs(*f) > math.MaxFloat32 {
			return nil, false
		}
		b = binary.LittleEndian.AppendUint32(b, math.Float32bits(float32(*f)))
	}
	return b, true
}
