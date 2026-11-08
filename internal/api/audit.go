package api

import (
	"net/http"
	"strconv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.ListAudit(r.Context(), p, r.URL.Query().Get("after"), limit)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}
