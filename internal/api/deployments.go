package api

import (
	"context"
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func catalogMutation[T any](s *Server, w http.ResponseWriter, r *http.Request, mutate func(context.Context, controlplane.Principal, string, T) (controlplane.APIReceipt, error)) {
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var input T
	if !decode(w, r, &input) {
		return
	}
	out, err := mutate(r.Context(), p, key, input)
	receipt(w, out, err)
}
func (s *Server) systemImages(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	if r.Method == "POST" {
		catalogMutation(s, w, r, s.catalog.ApproveSystemImage)
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	after, limit, ok := teamPagination(w, r)
	if !ok {
		return
	}
	items, err := s.catalog.SystemImages(r.Context(), p, after, limit)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"items": items})
}
func (s *Server) publishTemplate(w http.ResponseWriter, r *http.Request) {
	if method(w, r, "POST") {
		catalogMutation(s, w, r, s.catalog.PublishTemplate)
	}
}
func (s *Server) planDeployment(w http.ResponseWriter, r *http.Request) {
	if method(w, r, "POST") {
		catalogMutation(s, w, r, s.catalog.PlanDeployment)
	}
}
func (s *Server) applyDeployment(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	catalogMutation(s, w, r, func(ctx context.Context, p controlplane.Principal, key string, _ struct{}) (controlplane.APIReceipt, error) {
		return s.catalog.ApplyDeployment(ctx, p, r.PathValue("id"), key)
	})
}
func (s *Server) showDeployment(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.catalog.GetDeployment(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}
func (s *Server) createPool(w http.ResponseWriter, r *http.Request) {
	if method(w, r, "POST") {
		catalogMutation(s, w, r, s.catalog.CreatePool)
	}
}
func (s *Server) showPool(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.catalog.GetPool(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

func (s *Server) resizeAgent(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	catalogMutation(s, w, r, func(ctx context.Context, p controlplane.Principal, key string, in controlplane.ComputeResources) (controlplane.APIReceipt, error) {
		return s.catalog.ResizeAgent(ctx, p, r.PathValue("id"), key, in)
	})
}

func (s *Server) startRollout(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	catalogMutation(s, w, r, func(ctx context.Context, p controlplane.Principal, key string, in controlplane.RolloutInput) (controlplane.APIReceipt, error) {
		return s.catalog.StartRollout(ctx, p, r.PathValue("id"), key, in)
	})
}
func (s *Server) showRollout(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.catalog.GetRollout(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}
func (s *Server) resumeRollout(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	catalogMutation(s, w, r, func(ctx context.Context, p controlplane.Principal, key string, _ struct{}) (controlplane.APIReceipt, error) {
		return s.catalog.ResumeRollout(ctx, p, r.PathValue("id"), key)
	})
}
func (s *Server) rolloutMembers(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	after, limit, ok := teamPagination(w, r)
	if !ok {
		return
	}
	out, err := s.catalog.RolloutMembers(r.Context(), p, r.PathValue("id"), after, limit)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) requestGrowth(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	catalogMutation(s, w, r, func(ctx context.Context, p controlplane.Principal, key string, in controlplane.GrowthInput) (controlplane.APIReceipt, error) {
		return s.catalog.RequestGrowth(ctx, p, r.PathValue("id"), key, in)
	})
}
func (s *Server) showGrowth(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.catalog.GetGrowth(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}
