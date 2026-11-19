package api

import (
	"net/http"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) applicationRoutes() {
	s.handle("/v1/applications", s.applications)
	s.handle("/v1/applications/{id}", s.application)
	s.handle("/v1/applications/{id}/rotate", s.rotateApplication)
	s.handle("/v1/applications/{id}/revoke", s.revokeApplication)
	s.handle("/v1/assignment-policies/plan", s.planPolicy)
	s.handle("/v1/assignment-policies/{id}/apply", s.applyPolicy)
	s.handle("/v1/applications/{id}/invitations", s.invite)
	s.handle("/v1/applications/{id}/accept", s.acceptInvitation)
	s.handle("/v1/applications/{id}/activations/{activation_id}", s.activation)
	s.handle("/v1/access/explain", s.accessExplanation)
}
func (s *Server) applications(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.accounts.ListApplications(r.Context(), p, after, limit)
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
	var in controlplane.ApplicationConfig
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.RegisterApplication(r.Context(), p, key, in)
	receipt(w, out, err)
}
func (s *Server) application(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	v, err := s.accounts.ShowApplication(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, v)
}

func appMutation[T any](s *Server, w http.ResponseWriter, r *http.Request, m string, fn func(controlplane.Principal, string, T) (controlplane.APIReceipt, error)) {
	if !method(w, r, m) {
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
	var in T
	if !decode(w, r, &in) {
		return
	}
	out, err := fn(p, key, in)
	receipt(w, out, err)
}
func (s *Server) rotateApplication(w http.ResponseWriter, r *http.Request) {
	appMutation(s, w, r, "POST", func(p controlplane.Principal, key string, in controlplane.RotateApplication) (controlplane.APIReceipt, error) {
		return s.accounts.ChangeApplication(r.Context(), p, r.PathValue("id"), key, &in)
	})
}
func (s *Server) revokeApplication(w http.ResponseWriter, r *http.Request) {
	appMutation(s, w, r, "POST", func(p controlplane.Principal, key string, _ struct{}) (controlplane.APIReceipt, error) {
		return s.accounts.ChangeApplication(r.Context(), p, r.PathValue("id"), key, nil)
	})
}
func (s *Server) planPolicy(w http.ResponseWriter, r *http.Request) {
	appMutation(s, w, r, "POST", func(p controlplane.Principal, key string, in controlplane.PolicySpec) (controlplane.APIReceipt, error) {
		return s.accounts.PlanPolicy(r.Context(), p, key, in)
	})
}
func (s *Server) applyPolicy(w http.ResponseWriter, r *http.Request) {
	appMutation(s, w, r, "POST", func(p controlplane.Principal, key string, _ struct{}) (controlplane.APIReceipt, error) {
		return s.accounts.ApplyPolicy(r.Context(), p, r.PathValue("id"), key)
	})
}
func (s *Server) invite(w http.ResponseWriter, r *http.Request) {
	appMutation(s, w, r, "POST", func(p controlplane.Principal, key string, in controlplane.InviteInput) (controlplane.APIReceipt, error) {
		return s.accounts.Invite(r.Context(), p, r.PathValue("id"), key, in)
	})
}
func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		failure(w, controlplane.ErrAuthentication)
		return
	}
	parts := strings.Fields(headers[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		failure(w, controlplane.ErrAuthentication)
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.AcceptInvitation
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.AcceptInvitation(r.Context(), r.PathValue("id"), key, parts[1], in)
	receipt(w, out, err)
}
func (s *Server) activation(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "PUT") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	app, id := r.PathValue("id"), r.PathValue("activation_id")
	if r.Method == "GET" {
		v, err := s.accounts.ShowActivation(r.Context(), p, app, id)
		if err != nil {
			failure(w, err)
			return
		}
		if v.RetryAfter > 0 {
			w.Header().Set("Retry-After", "5")
		}
		jsonResponse(w, 200, v)
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.MemberEvent
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.SyncActivation(r.Context(), p, app, id, key, in)
	receipt(w, out, err)
}
func (s *Server) accessExplanation(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	v, err := s.accounts.ExplainAccess(r.Context(), p, r.URL.Query().Get("member"), r.URL.Query().Get("agent"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, v)
}
