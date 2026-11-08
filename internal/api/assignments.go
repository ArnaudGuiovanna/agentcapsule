package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) assignments(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.accounts.ListAgentAssignments(r.Context(), p, r.PathValue("id"), after, limit)
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
	var in controlplane.CreateAssignmentInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreateAgentAssignment(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}

func (s *Server) revokeAssignment(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.RevokeAgentAssignment(r.Context(), p, r.PathValue("id"), r.PathValue("assignment_id"), key)
	receipt(w, out, err)
}

func (s *Server) replaceAssignment(w http.ResponseWriter, r *http.Request) {
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
		Permissions []string `json:"permissions"`
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.ReplaceAgentAssignment(r.Context(), p, r.PathValue("id"), r.PathValue("assignment_id"), key, in.Permissions)
	receipt(w, out, err)
}
