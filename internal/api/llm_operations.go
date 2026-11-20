package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// setLLMAliasOperations replaces the operations an alias's model serves
// (ADR 023 §12).
func (s *Server) setLLMAliasOperations(w http.ResponseWriter, r *http.Request) {
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
	var in controlplane.SetLLMAliasOperationsInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.SetLLMAliasOperations(r.Context(), p, r.PathValue("alias"), key, in)
	receipt(w, out, err)
}
