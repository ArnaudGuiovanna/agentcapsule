package llmgateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
)

// OCR sends one image or PDF to an openai_compatible provider that serves
// Mistral's OCR API (POST /ocr), as a data URL. For a PDF it asks for the
// declared pages only (indices 0 to pages-1), so the provider processes no
// page past the reservation. Retries, breaker and outcome rules are those of
// Complete.
func (g *Gateway) OCR(ctx context.Context, route Route, q OCRRequest) (out OCRResponse, err error) {
	ctx, span := startCall(ctx, "ocr", route)
	defer func() { endCall(span, Usage{}, err) }()
	if !q.Valid() || !route.validAuth() || route.UpstreamModel == "" {
		return OCRResponse{}, ErrInvalid
	}
	if route.Kind != "openai_compatible" {
		return OCRResponse{}, ErrUnsupported
	}
	url := "data:" + q.MediaType + ";base64," + base64.StdEncoding.EncodeToString(q.Document)
	document := map[string]string{"type": "image_url", "image_url": url}
	payload := map[string]any{"model": route.UpstreamModel, "document": document, "include_image_base64": false}
	if q.MediaType == "application/pdf" {
		document = map[string]string{"type": "document_url", "document_url": url}
		pages := make([]int, q.Pages)
		for i := range pages {
			pages[i] = i
		}
		payload["document"], payload["pages"] = document, pages
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return OCRResponse{}, ErrInvalid
	}
	var answer OCRResponse
	err = g.exchange(ctx, route.Key, join(route.BaseURL, "/ocr"), body, route.headers(), func(raw []byte) (err error) {
		answer, err = parseOCR(raw)
		return err
	})
	if err != nil {
		return OCRResponse{}, err
	}
	return answer, nil
}

func parseOCR(raw []byte) (OCRResponse, error) {
	var v struct {
		Pages []struct {
			Index    *int    `json:"index"`
			Markdown *string `json:"markdown"`
		} `json:"pages"`
		UsageInfo struct {
			PagesProcessed int64 `json:"pages_processed"`
		} `json:"usage_info"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Pages == nil || v.UsageInfo.PagesProcessed < 0 || v.UsageInfo.PagesProcessed > 1_000_000 {
		return OCRResponse{}, ErrInvalid
	}
	out := OCRResponse{Pages: make([]OCRPage, 0, len(v.Pages)), PagesProcessed: v.UsageInfo.PagesProcessed}
	for _, p := range v.Pages {
		if p.Index == nil || *p.Index < 0 || p.Markdown == nil {
			return OCRResponse{}, ErrInvalid
		}
		out.Pages = append(out.Pages, OCRPage{Index: *p.Index, Markdown: *p.Markdown})
	}
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) > MaxForwardBytes {
		return OCRResponse{}, ErrInvalid
	}
	return out, nil
}
