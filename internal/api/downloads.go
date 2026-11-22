package api

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// A link is minted with the caller's bearer, then fetched without one. Minting
// stores nothing (the link is sealed), so it takes no Idempotency-Key: two
// calls give two links to the same content (ADR 016).
func (s *Server) mintLink(w http.ResponseWriter, r *http.Request, mint func(controlplane.Principal, int) (controlplane.DownloadLink, error)) {
	if !method(w, r, "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	ttl := 0
	if raw := r.URL.Query().Get("ttl_seconds"); raw != "" {
		var err error
		if ttl, err = strconv.Atoi(raw); err != nil || ttl == 0 {
			failure(w, controlplane.ErrInput)
			return
		}
	}
	out, err := mint(p, ttl)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, out)
}

func (s *Server) attachmentLink(w http.ResponseWriter, r *http.Request) {
	s.mintLink(w, r, func(p controlplane.Principal, ttl int) (controlplane.DownloadLink, error) {
		return s.catalog.AttachmentLink(r.Context(), p, r.PathValue("id"), ttl)
	})
}

func (s *Server) resultLink(w http.ResponseWriter, r *http.Request) {
	s.mintLink(w, r, func(p controlplane.Principal, ttl int) (controlplane.DownloadLink, error) {
		return s.catalog.ResultLink(r.Context(), p, r.PathValue("id"), ttl)
	})
}

// downloadWriteTimeout bounds how long one download may take to leave: 8 MiB
// at 70 KB/s. The server-wide write timeout is sized for small answers
// (v0.1.0 audit, L-05).
const downloadWriteTimeout = 2 * time.Minute

// downloadLink serves what a link opens. It needs no Authorization header:
// the link carries the identity it was minted for, checked again now. Every
// refusal is the same 404. The request log records the route pattern, never
// the link. Its downloads are charged to that identity's limits, read from
// the link's seal before any database work.
func (s *Server) downloadLink(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	if l := s.guards.requests; l != nil {
		holder, err := s.catalog.DownloadHolder(r.PathValue("token"))
		if err != nil {
			failure(w, err)
			return
		}
		if limit, wait := l.admit(holder); limit != "" {
			s.refuseLimited(w, limit, wait)
			return
		}
	}
	out, err := s.catalog.OpenDownload(r.Context(), r.PathValue("token"))
	if err != nil {
		failure(w, err)
		return
	}
	defer clear(out.Body)
	h := w.Header()
	h.Set("Content-Type", out.MediaType)
	h.Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(out.Name))
	h.Set("Content-Length", strconv.Itoa(len(out.Body)))
	h.Set("X-Content-SHA256", out.SHA256)
	h.Set("Referrer-Policy", "no-referrer")
	// The body may take longer than the server's write timeout to reach a
	// slow client: the deadline moves, as an upload's does.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(downloadWriteTimeout))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Body)
}
