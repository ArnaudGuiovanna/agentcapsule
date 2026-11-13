package api

import (
	"net/http"
	"strconv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// heldRequests lists the requests an organization agent holds for approval.
func (s *Server) heldRequests(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		if limit, err = strconv.Atoi(raw); err != nil {
			failure(w, controlplane.ErrInput)
			return
		}
	}
	items, err := s.catalog.HeldRequests(r.Context(), p, r.PathValue("id"), r.URL.Query().Get("after"), limit)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) acceptHeldRequest(w http.ResponseWriter, r *http.Request) {
	s.decideHeldRequest(w, r, true)
}

func (s *Server) declineHeldRequest(w http.ResponseWriter, r *http.Request) {
	s.decideHeldRequest(w, r, false)
}

func (s *Server) decideHeldRequest(w http.ResponseWriter, r *http.Request, accept bool) {
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
	out, err := s.catalog.DecideHeldRequest(r.Context(), p, r.PathValue("id"), r.PathValue("request_id"), key, accept)
	receipt(w, out, err)
}
