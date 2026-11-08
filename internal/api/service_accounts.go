package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) serviceAccounts(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.accounts.ListServiceAccounts(r.Context(), p, after, limit)
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
	var in controlplane.CreateServiceAccountInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreateServiceAccount(r.Context(), p, key, in)
	receipt(w, out, err)
}

func (s *Server) disableServiceAccount(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.DisableServiceAccount(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}

func (s *Server) serviceTokens(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.accounts.ListServiceTokens(r.Context(), p, r.PathValue("id"), after, limit)
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
	var in controlplane.IssueServiceTokenInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.IssueServiceToken(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}

func (s *Server) revokeServiceToken(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.RevokeServiceToken(r.Context(), p, r.PathValue("id"), r.PathValue("token_id"), key)
	receipt(w, out, err)
}
