package api

import (
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"net/http"
	"strconv"
)

func (s *Server) instruct(w http.ResponseWriter, r *http.Request) {
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
	var in controlplane.OwnerInstruction
	if !decode(w, r, &in) {
		return
	}
	out, err := s.catalog.Instruct(r.Context(), p, r.PathValue("id"), key, in)
	if err == nil {
		w.Header().Set("Retry-After", "1")
	}
	receipt(w, out, err)
}

func (s *Server) instructionResult(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.catalog.InstructionResult(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	defer clear(out)
	jsonResponse(w, http.StatusOK, out)
}

// invocations is the structured resource for a request to a tenant agent.
// It shares admission with the messages route but answers with an invocation.
func (s *Server) invocations(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var err error
			if limit, err = strconv.Atoi(raw); err != nil {
				failure(w, controlplane.ErrInput)
				return
			}
		}
		items, err := s.catalog.ListInvocations(r.Context(), p, r.PathValue("id"), r.URL.Query().Get("after"), r.URL.Query().Get("state"), limit)
		if err != nil {
			failure(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.InvocationInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.catalog.CreateInvocation(r.Context(), p, r.PathValue("id"), key, in)
	if err == nil {
		w.Header().Set("Retry-After", "1")
	}
	receipt(w, out, err)
}

func (s *Server) invocation(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.catalog.GetInvocation(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

// cancelInvocation cancels a scheduled invocation that has not been released.
func (s *Server) cancelInvocation(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.catalog.CancelInvocation(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}

// idlePolicy sets or clears the idle-closure timeout of one agent.
func (s *Server) idlePolicy(w http.ResponseWriter, r *http.Request) {
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
		Seconds *int `json:"idle_timeout_seconds"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Seconds == nil {
		failure(w, controlplane.ErrInput)
		return
	}
	out, err := s.catalog.SetIdlePolicy(r.Context(), p, r.PathValue("id"), key, *in.Seconds)
	receipt(w, out, err)
}
