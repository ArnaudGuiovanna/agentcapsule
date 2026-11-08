package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) llmProviders(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		after, limit, ok := teamPagination(w, r)
		if !ok {
			return
		}
		items, err := s.accounts.ListLLMProviders(r.Context(), p, after, limit)
		if err != nil {
			failure(w, err)
			return
		}
		jsonResponse(w, 200, map[string]any{"items": items})
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.CreateLLMProviderInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreateLLMProvider(r.Context(), p, key, in)
	receipt(w, out, err)
}

func (s *Server) rotateLLMProvider(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in struct {
		Secret string `json:"secret"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.RotateLLMProviderSecret(r.Context(), p, r.PathValue("id"), key, in.Secret)
	receipt(w, out, err)
}

func (s *Server) disableLLMProvider(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.DisableLLMProvider(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}

func (s *Server) llmAliases(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		after, limit, ok := teamPagination(w, r)
		if !ok {
			return
		}
		items, err := s.accounts.ListLLMAliases(r.Context(), p, after, limit)
		if err != nil {
			failure(w, err)
			return
		}
		jsonResponse(w, 200, map[string]any{"items": items})
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.CreateLLMAliasInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreateLLMAlias(r.Context(), p, key, in)
	receipt(w, out, err)
}

func (s *Server) disableLLMAlias(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.DisableLLMAlias(r.Context(), p, r.PathValue("alias"), key)
	receipt(w, out, err)
}

func (s *Server) llmBudgets(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		after, limit, ok := teamPagination(w, r)
		if !ok {
			return
		}
		items, err := s.accounts.ListLLMBudgets(r.Context(), p, after, limit)
		if err != nil {
			failure(w, err)
			return
		}
		jsonResponse(w, 200, map[string]any{"items": items})
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.CreateLLMBudgetInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreateLLMBudget(r.Context(), p, key, in)
	receipt(w, out, err)
}

func (s *Server) disableLLMBudget(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in struct{}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.DisableLLMBudget(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}

func (s *Server) llmUsage(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "day"
	}
	rep, err := s.accounts.LLMUsage(r.Context(), p, period)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, rep)
}

// queue shows instruction-queue limits and depth (usage:read, administrative).
func (s *Server) queue(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.accounts.QueueStatus(r.Context(), p)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, out)
}

// queueLimits replaces the organization's depth limits (quota:manage).
func (s *Server) queueLimits(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.QueueLimits
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.SetQueueLimits(r.Context(), p, key, in)
	receipt(w, out, err)
}
