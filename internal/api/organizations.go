package api

import (
	"net/http"
	"strconv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) organizations(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.accounts.ListOrganizations(r.Context(), p, r.URL.Query().Get("after"), limit)
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
	var input controlplane.CreateOrganizationInput
	if !decode(w, r, &input) {
		return
	}
	out, err := s.accounts.CreateOrganization(r.Context(), p, key, input)
	receipt(w, out, err)
}

func (s *Server) organization(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	o, err := s.accounts.GetOrganization(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, o)
}

func (s *Server) disableOrganization(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.DisableOrganization(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}
