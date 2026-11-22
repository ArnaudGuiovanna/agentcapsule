package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// The platform operator approves an application's OIDC client for one
// organization (controlplane/application_clients.go, finding S-10).
func (s *Server) applicationClientRoutes() {
	s.handle("/v1/organizations/{id}/application-clients", s.applicationClients)
	s.handle("/v1/organizations/{id}/application-clients/{approval_id}/withdraw", s.withdrawApplicationClient)
}

func (s *Server) applicationClients(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.accounts.ListApplicationClients(r.Context(), p, r.PathValue("id"), after, limit)
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
	var in controlplane.ApplicationClientInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.ApproveApplicationClient(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}

func (s *Server) withdrawApplicationClient(w http.ResponseWriter, r *http.Request) {
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
	if !decode(w, r, &struct{}{}) {
		return
	}
	out, err := s.accounts.WithdrawApplicationClient(r.Context(), p, r.PathValue("id"), r.PathValue("approval_id"), key)
	receipt(w, out, err)
}
