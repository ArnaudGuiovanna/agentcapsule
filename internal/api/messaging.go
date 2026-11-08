package api

import (
	"net/http"
	"strconv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) messagingSettings(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "PUT") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	var update *controlplane.MessagingSettings
	if r.Method == "PUT" {
		var in struct {
			Discoverable *bool   `json:"discoverable"`
			InboundMode  *string `json:"inbound_mode"`
		}
		if !decode(w, r, &in) {
			return
		}
		if in.Discoverable == nil || in.InboundMode == nil {
			failure(w, controlplane.ErrInput)
			return
		}
		update = &controlplane.MessagingSettings{Discoverable: *in.Discoverable, InboundMode: *in.InboundMode}
	}
	settings, err := s.catalog.MessagingSettings(r.Context(), p, update)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, settings)
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
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
		limit, err = strconv.Atoi(raw)
		if err != nil {
			failure(w, controlplane.ErrInput)
			return
		}
	}
	items, err := s.catalog.Inbox(r.Context(), p, r.URL.Query().Get("after"), r.URL.Query().Get("state"), limit)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}

func (s *Server) acceptRequest(w http.ResponseWriter, r *http.Request) { s.decideRequest(w, r, true) }

func (s *Server) cancelRequest(w http.ResponseWriter, r *http.Request) {
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
	var input struct{}
	if !decode(w, r, &input) {
		return
	}
	out, err := s.catalog.CancelRequest(r.Context(), p, r.PathValue("id"), key)
	if err == nil {
		w.Header().Set("Retry-After", "1")
	}
	receipt(w, out, err)
}

func (s *Server) ownerMessage(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	result, err := s.catalog.OwnerMessage(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, result)
}
func (s *Server) declineRequest(w http.ResponseWriter, r *http.Request) { s.decideRequest(w, r, false) }
func (s *Server) decideRequest(w http.ResponseWriter, r *http.Request, accept bool) {
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
	result, err := s.catalog.DecideRequest(r.Context(), p, r.PathValue("id"), key, accept)
	if err != nil {
		failure(w, err)
		return
	}
	if result.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	jsonResponse(w, 200, result)
}

func (s *Server) agentRequest(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	result, err := s.catalog.Request(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, result)
}
