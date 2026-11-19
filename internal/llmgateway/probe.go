package llmgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProbeResult separates transport and model catalog evidence from an
// actual, billable generation. No response content or headers leave the host.
type ProbeResult struct {
	Endpoint    string    `json:"endpoint"`
	Model       string    `json:"model"`
	Protocol    string    `json:"protocol"`
	HTTPStatus  int       `json:"http_status"`
	ModelListed bool      `json:"model_listed"`
	Observation string    `json:"observation"`
	ObservedAt  time.Time `json:"observed_at"`
}

func (g *Gateway) Probe(ctx context.Context, r Route) (ProbeResult, error) {
	out := ProbeResult{Endpoint: r.BaseURL, Model: r.UpstreamModel, Protocol: r.Kind, ObservedAt: time.Now().UTC()}
	if !r.validAuth() || r.UpstreamModel == "" {
		return out, ErrInvalid
	}
	suffix := "/models"
	switch r.Kind {
	case "openai_compatible":
	case "anthropic":
		suffix = "/v1/models"
	default:
		return out, ErrInvalid
	}
	target := join(r.BaseURL, suffix)
	if g.cfg.RequireHTTPS && !strings.HasPrefix(target, "https://") {
		return out, ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return out, ErrInvalid
	}
	for k, v := range r.headers() {
		req.Header.Set(k, v)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrAddressRefused) {
			return out, ErrAddressRefused
		}
		return out, ErrUnavailable
	}
	defer resp.Body.Close()
	out.HTTPStatus = resp.StatusCode
	if resp.StatusCode != 200 {
		out.Observation = "catalog_http_failure"
		return out, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	var catalog struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &catalog) != nil || catalog.Data == nil {
		out.Observation = "catalog_unreadable"
		return out, nil
	}
	out.Observation = "model_not_in_returned_page"
	for _, model := range catalog.Data {
		if model.ID == r.UpstreamModel {
			out.ModelListed = true
			out.Observation = "model_listed"
			break
		}
	}
	return out, nil
}
