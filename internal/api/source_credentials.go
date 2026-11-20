package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// sourceCredentials lists the organization's source credentials, metadata
// only, or stores a new one (ADR 023 §3.1, corpus:manage).
func (s *Server) sourceCredentials(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.accounts.ListSourceCredentials(r.Context(), p, after, limit)
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
	var in controlplane.CreateSourceCredentialInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreateSourceCredential(r.Context(), p, key, in)
	receipt(w, out, err)
}

func (s *Server) rotateSourceCredential(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.RotateSourceCredential(r.Context(), p, r.PathValue("id"), key, in.Secret)
	receipt(w, out, err)
}

func (s *Server) disableSourceCredential(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.DisableSourceCredential(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}
