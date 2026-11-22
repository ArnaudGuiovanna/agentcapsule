package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	if method(w, r, "GET") {
		jsonResponse(w, 200, map[string]int{"api_major": 1, "cli_protocol": 1})
	}
}
func (s *Server) platformDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.store.PlatformDiagnostics(r.Context(), p)
	if err != nil {
		failure(w, err)
		return
	}
	// Operator-defined host names are labels. API fields ending in _id
	// carry opaque resource identifiers.
	type host struct {
		Name string `json:"host"`
		controlplane.HostStatistics
	}
	hosts := make([]host, 0, len(out.Hosts))
	for _, h := range out.Hosts {
		hosts = append(hosts, host{h.HostID, h.HostStatistics})
	}
	diagnostics := struct {
		controlplane.Diagnostics
		Hosts []host `json:"hosts"`
	}{out, hosts}
	jsonResponse(w, 200, map[string]any{"observed_at": time.Now().UTC(), "diagnostics": diagnostics})
}
func (s *Server) platformSession(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	out, err := s.store.PlatformSession(r.Context(), p)
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, out)
}

func (s *Server) createPlatformSession(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "POST") {
		return
	}
	var p controlplane.Principal
	var enrollment string
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(r.Header.Values("Authorization")) == 1 && len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") && strings.HasPrefix(fields[1], "acpe_") && len(fields[1]) == 48 {
		if !s.admitAttempt(w, r) {
			return
		}
		enrollment = fields[1]
	} else {
		var ok bool
		p, ok = s.principal(w, r)
		if !ok {
			return
		}
	}
	key, ok := idempotency(w, r)
	if !ok {
		return
	}
	var in controlplane.PlatformSessionRequest
	if !decode(w, r, &in) {
		return
	}
	out, err := s.accounts.CreatePlatformSession(r.Context(), p, enrollment, key, in)
	receipt(w, out, err)
}

func (s *Server) revokePlatformSession(w http.ResponseWriter, r *http.Request) {
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
	if !decode(w, r, &struct{}{}) {
		return
	}
	out, err := s.accounts.RevokePlatformSession(r.Context(), p, r.PathValue("id"), key)
	receipt(w, out, err)
}
