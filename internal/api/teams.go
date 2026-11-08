package api

import (
	"net/http"
	"strconv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func teamPagination(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			failure(w, controlplane.ErrInput)
			return "", 0, false
		}
	}
	return r.URL.Query().Get("after"), limit, true
}
func (s *Server) teams(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		after, limit, ok := teamPagination(w, r)
		if !ok {
			return
		}
		items, err := s.accounts.ListTeams(r.Context(), p, after, limit)
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
	var in controlplane.CreateTeamInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreateTeam(r.Context(), p, key, in)
	receipt(w, out, err)
}
func (s *Server) team(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.accounts.GetTeam(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, out)
}
func (s *Server) disableTeam(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.DisableTeam(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}
func (s *Server) teamMembers(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		after, limit, ok := teamPagination(w, r)
		if !ok {
			return
		}
		items, err := s.accounts.ListTeamMembers(r.Context(), p, r.PathValue("id"), after, limit)
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
	var in controlplane.AddTeamMemberInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.AddTeamMember(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}
func (s *Server) revokeTeamMember(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.RevokeTeamMember(r.Context(), p, r.PathValue("id"), r.PathValue("principal_id"), key)
	receipt(w, out, err)
}
