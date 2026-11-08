package api

import (
	"net/http"
	"strconv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) agents(w http.ResponseWriter, r *http.Request) {
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
			limit, err = strconv.Atoi(raw)
			if err != nil {
				failure(w, controlplane.ErrInput)
				return
			}
		}
		if p.Kind == "tenant" {
			items, err := s.catalog.ListTenantAgents(r.Context(), p, r.URL.Query().Get("after"), limit)
			if err != nil {
				failure(w, err)
				return
			}
			jsonResponse(w, http.StatusOK, map[string]any{"items": items})
			return
		}
		items, err := s.catalog.List(r.Context(), p, r.URL.Query().Get("after"), limit)
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
	var in controlplane.CreateAgentInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.catalog.Reserve(r.Context(), p, key, in)
	if err == nil {
		// The receipt identifies a durable operation even when the worker has
		// not yet created a volume. Its original body is stable on replay.
		w.Header().Set("Retry-After", "1")
	}
	receipt(w, out, err)
}
func (s *Server) agent(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "DELETE") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "DELETE" {
		key, ok := idempotency(w, r)
		if !ok {
			return
		}
		if r.ContentLength != 0 {
			var input struct{}
			if !decode(w, r, &input) {
				return
			}
		}
		out, err := s.catalog.Delete(r.Context(), p, r.PathValue("id"), key)
		if err == nil {
			w.Header().Set("Retry-After", "1")
		}
		receipt(w, out, err)
		return
	}
	if p.Kind == "tenant" {
		out, err := s.catalog.GetTenantAgent(r.Context(), p, r.PathValue("id"))
		if err != nil {
			failure(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, out)
		return
	}
	out, err := s.catalog.Get(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}
func (s *Server) operation(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.catalog.Operation(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

func (s *Server) wake(w http.ResponseWriter, r *http.Request)  { s.lifecycle(w, r, "wake") }
func (s *Server) sleep(w http.ResponseWriter, r *http.Request) { s.lifecycle(w, r, "sleep") }
func (s *Server) lifecycle(w http.ResponseWriter, r *http.Request, kind string) {
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
	var input struct{}
	if !decode(w, r, &input) {
		return
	}
	out, err := s.catalog.RequestLifecycle(r.Context(), p, r.PathValue("id"), key, kind)
	receipt(w, out, err)
}
