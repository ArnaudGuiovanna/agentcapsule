package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
)

// SetDelegatedIdentityVerifier swaps local verification config. This does not
// activate its fingerprints in PostgreSQL; only an explicit operator change
// can do that. Nil disables JWT authentication. The pointer is concurrency-safe.
func (s *Server) SetDelegatedIdentityVerifier(v *delegatedidentity.Verifier) {
	s.delegations.Store(v)
}

func (s *Server) currentOrganization(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.accounts.CurrentOrganization(r.Context(), p)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, out)
}
