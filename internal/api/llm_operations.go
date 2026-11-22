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

// setLLMAliasRequestPolicy replaces what an alias lets a call ask of its
// provider: the fields and tool types a forwarded request may use beside the
// plain ones, and the output cap of a call that declares none (v0.1.0 audit,
// S-11 and S-13).
func (s *Server) setLLMAliasRequestPolicy(w http.ResponseWriter, r *http.Request) {
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
	var in controlplane.SetLLMAliasRequestPolicyInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.SetLLMAliasRequestPolicy(r.Context(), p, r.PathValue("alias"), key, in)
	receipt(w, out, err)
}
