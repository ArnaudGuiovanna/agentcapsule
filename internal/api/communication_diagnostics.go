package api

import "net/http"

func (s *Server) explainCommunication(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	d, err := s.catalog.ExplainCommunication(r.Context(), p, r.PathValue("id"), r.PathValue("request_id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, 200, d)
}
