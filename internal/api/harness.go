package api

import (
	"net/http"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// harnessImports starts an asynchronous import of a package pinned by digest
// (platform operator only).
func (s *Server) harnessImports(w http.ResponseWriter, r *http.Request) {
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
	var in controlplane.HarnessImportInput
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.RequestHarnessImport(r.Context(), p, key, in)
	receipt(w, out, err)
}

func (s *Server) harnessImport(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.accounts.GetHarnessImport(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

// harnessReleases lists releases to the platform operator and to organization
// members allowed to read agents.
func (s *Server) harnessReleases(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	include := false
	switch r.URL.Query().Get("include_deprecated") {
	case "", "false":
	case "true":
		include = true
	default:
		failure(w, controlplane.ErrInput)
		return
	}
	items, err := s.accounts.ListHarnessReleases(r.Context(), p, include)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) deprecateHarnessRelease(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.accounts.DeprecateHarnessRelease(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}

// agentRelease pins an agent to another approved release (upgrade or
// rollback). It takes effect at the agent's next boot.
func (s *Server) agentRelease(w http.ResponseWriter, r *http.Request) {
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
	var in controlplane.ReleaseChange
	if !decode(w, r, &in) {
		return
	}
	out, err := s.catalog.ChangeAgentRelease(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}

// agentDirectory reads (GET) or sets (PUT) how an organization agent is
// described in the private Directory.
func (s *Server) agentDirectory(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "PUT") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	if r.Method == "GET" {
		out, err := s.catalog.GetDirectoryProfile(r.Context(), p, r.PathValue("id"))
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
	var in controlplane.DirectoryProfile
	if !decode(w, r, &in) {
		return
	}
	out, err := s.catalog.SetDirectoryProfile(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}
