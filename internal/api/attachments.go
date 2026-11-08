package api

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// attachmentReadTimeout bounds how long one upload may take to arrive. The
// server-wide read timeout is sized for small JSON bodies.
const attachmentReadTimeout = 2 * time.Minute

// attachments receives one file as the raw request body:
//
//	POST /v1/agents/{id}/attachments?ttl_seconds=N
//	Content-Type: <media type>   (parameters such as charset are not kept)
//	X-Attachment-Name: <percent-encoded UTF-8 file name>
//	X-Content-SHA256: <optional lowercase hex digest, checked before storing>
//
// The principal is authenticated before the body is read. The body is held in
// memory (at most capsuleprotocol.MaxAttachmentBytes) and encrypted before it
// reaches PostgreSQL.
func (s *Server) attachments(w http.ResponseWriter, r *http.Request) {
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
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !capsuleprotocol.ValidAttachmentType(media) {
		problem(w, 415, "media_type_required")
		return
	}
	names := r.Header.Values("X-Attachment-Name")
	if len(names) != 1 {
		failure(w, controlplane.ErrInput)
		return
	}
	name, err := url.PathUnescape(names[0])
	if err != nil {
		failure(w, controlplane.ErrInput)
		return
	}
	ttl := 0
	if raw := r.URL.Query().Get("ttl_seconds"); raw != "" {
		if ttl, err = strconv.Atoi(raw); err != nil {
			failure(w, controlplane.ErrInput)
			return
		}
	}
	if r.ContentLength > capsuleprotocol.MaxAttachmentBytes {
		failure(w, controlplane.ErrTooLarge)
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(attachmentReadTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(attachmentReadTimeout + 15*time.Second))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, capsuleprotocol.MaxAttachmentBytes))
	defer clear(body)
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			failure(w, controlplane.ErrTooLarge)
		} else {
			problem(w, 400, "incomplete_body")
		}
		return
	}
	// The request context's deadline was sized for small requests and may have
	// passed while a large body arrived; the database work gets its own bound.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	out, err := s.catalog.UploadAttachment(ctx, p, r.PathValue("id"), key, controlplane.AttachmentUpload{
		Name: name, MediaType: media, DeclaredSHA256: r.Header.Get("X-Content-SHA256"), TTLSeconds: ttl}, body)
	receipt(w, out, err)
}

// attachment shows an attachment's metadata (never its bytes) or deletes one
// that is not yet bound to an invocation.
func (s *Server) attachment(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "DELETE") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		out, err := s.catalog.GetAttachment(r.Context(), p, r.PathValue("id"))
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
	out, err := s.catalog.DeleteAttachment(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}
