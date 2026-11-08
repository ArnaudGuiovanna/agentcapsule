package api

import (
	"net/http"
	"strconv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) members(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var err error
			limit, err = strconv.Atoi(raw)
			if err != nil {
				failure(w, controlplane.ErrInput)
				return
			}
		}
		items, err := s.accounts.ListMembers(r.Context(), p, r.URL.Query().Get("after"), limit)
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
	var in controlplane.CreateMemberInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreateMember(r.Context(), p, key, in)
	receipt(w, out, err)
}

func (s *Server) changeMemberRole(w http.ResponseWriter, r *http.Request) {
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
	var in controlplane.ChangeMemberRoleInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.ChangeMemberRole(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}

func (s *Server) revokeMember(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.RevokeMember(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}
