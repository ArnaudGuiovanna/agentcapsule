package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// agentCapabilities shows an agent's capability catalog (EXT-003) and sets
// what the agent allows (ADR 016).
func (s *Server) agentCapabilities(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "PUT") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		out, err := s.catalog.AgentCapabilities(r.Context(), p, r.PathValue("id"))
		if err != nil {
			failure(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, out)
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.CapabilityPolicy
	if !decode(w, r, &in) {
		return
	}
	out, err := s.catalog.SetAgentCapabilities(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}

// organizationCapabilities shows and sets what the organization allows.
func (s *Server) organizationCapabilities(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "PUT") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		out, err := s.accounts.OrganizationCapabilities(r.Context(), p)
		if err != nil {
			failure(w, err)
			return
		}
		jsonResponse(w, http.StatusOK, out)
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.CapabilityPolicy
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.SetOrganizationCapabilities(r.Context(), p, key, in)
	receipt(w, out, err)
}
