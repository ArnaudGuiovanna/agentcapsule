package api

import (
	"net/http"
	"strconv"
	"time"

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

// auditExport returns the organization's audit events of [from, to), RFC 3339
// times, at most 366 days, as one JSON document to download (TEN-06). The
// rights are those of GET /v1/audit.
func (s *Server) auditExport(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	from, err := time.Parse(time.RFC3339, q.Get("from"))
	if err != nil {
		failure(w, controlplane.ErrInput)
		return
	}
	to, err := time.Parse(time.RFC3339, q.Get("to"))
	if err != nil {
		failure(w, controlplane.ErrInput)
		return
	}
	out, err := s.accounts.ExportAudit(r.Context(), p, from, to)
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.json"`)
	jsonResponse(w, http.StatusOK, out)
}
