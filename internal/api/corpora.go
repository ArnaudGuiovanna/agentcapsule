package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func corpusGet[T any](s *Server, w http.ResponseWriter, r *http.Request, read func(context.Context, controlplane.Principal, string) (T, error)) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	v, err := read(r.Context(), p, r.PathValue("id"))
	if err != nil {
		failure(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, v)
}

type corpusMutation[T any] func(context.Context, controlplane.Principal, string, string, T) (controlplane.APIReceipt, error)

func corpusPost[T any](s *Server, w http.ResponseWriter, r *http.Request, mutate corpusMutation[T]) {
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
	var in T
	if !decode(w, r, &in) {
		return
	}
	out, err := mutate(r.Context(), p, r.PathValue("id"), key, in)
	receipt(w, out, err)
}

func corpusPage[T any](s *Server, w http.ResponseWriter, r *http.Request, id func(T) string, read func(context.Context, controlplane.Principal, string, int) ([]T, error)) {
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
	if len(after) > 100 || limit < 1 || limit > 200 {
		failure(w, controlplane.ErrInput)
		return
	}
	items, err := read(r.Context(), p, after, limit+1)
	if err != nil {
		failure(w, err)
		return
	}
	v := map[string]any{"items": items}
	if len(items) > limit {
		v["items"] = items[:limit]
		v["next"] = id(items[limit-1])
	}
	jsonResponse(w, 200, v)
}

func (s *Server) corpora(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	if r.Method == "POST" {
		corpusPost(s, w, r, func(ctx context.Context, p controlplane.Principal, _, key string, in controlplane.CreateCorpusInput) (controlplane.APIReceipt, error) {
			return s.accounts.CreateCorpus(ctx, p, key, in)
		})
		return
	}
	corpusPage(s, w, r, func(v controlplane.Corpus) string { return v.ID }, func(ctx context.Context, p controlplane.Principal, after string, limit int) ([]controlplane.Corpus, error) {
		return s.accounts.ListCorpora(ctx, p, r.URL.Query().Get("name"), after, limit)
	})
}
func (s *Server) corpus(w http.ResponseWriter, r *http.Request) {
	corpusGet(s, w, r, s.accounts.Corpus)
}
func (s *Server) corpusBuilds(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	corpusPage(s, w, r, func(v controlplane.CorpusBuild) string { return v.ID }, func(ctx context.Context, p controlplane.Principal, after string, limit int) ([]controlplane.CorpusBuild, error) {
		return s.accounts.ListCorpusBuilds(ctx, p, q.Get("corpus_id"), q.Get("state"), after, limit)
	})
}
func (s *Server) requestCorpusBuild(w http.ResponseWriter, r *http.Request) {
	corpusPost(s, w, r, s.accounts.RequestCorpusBuild)
}
func (s *Server) corpusBuild(w http.ResponseWriter, r *http.Request) {
	corpusGet(s, w, r, s.accounts.CorpusBuild)
}
func (s *Server) cancelCorpusBuild(w http.ResponseWriter, r *http.Request) {
	corpusPost(s, w, r, func(ctx context.Context, p controlplane.Principal, id, key string, _ struct{}) (controlplane.APIReceipt, error) {
		return s.accounts.CancelCorpusBuild(ctx, p, id, key)
	})
}
func (s *Server) corpusBuildReview(w http.ResponseWriter, r *http.Request) {
	corpusGet(s, w, r, s.accounts.CorpusBuildReview)
}
func (s *Server) corpusBuildReviewFile(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET") {
		return
	}
	p, ok := s.principal(w, r)
	if !ok {
		return
	}
	path := r.URL.Query().Get("path")
	v, err := s.catalog.ReadCorpusReviewFile(r.Context(), p, r.PathValue("id"), path)
	if err != nil {
		failure(w, err)
		return
	}
	mime := "text/markdown; charset=utf-8"
	if path == "report.json" {
		mime = "application/json"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	_, _ = w.Write(v)
}
func (s *Server) tryCorpusBuild(w http.ResponseWriter, r *http.Request) {
	corpusPost(s, w, r, s.accounts.TryCorpusBuild)
}
func (s *Server) publishCorpusBuild(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Version int `json:"version"`
	}
	corpusPost(s, w, r, func(ctx context.Context, p controlplane.Principal, id, key string, in request) (controlplane.APIReceipt, error) {
		return s.accounts.PublishCorpusBuild(ctx, p, id, key, in.Version)
	})
}
func (s *Server) corpusReleases(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	corpusPage(s, w, r, func(v controlplane.CorpusRelease) string { return v.ID }, func(ctx context.Context, p controlplane.Principal, after string, limit int) ([]controlplane.CorpusRelease, error) {
		var include bool
		var err error
		if q.Has("include_deprecated") {
			include, err = strconv.ParseBool(q.Get("include_deprecated"))
			if err != nil {
				return nil, controlplane.ErrInput
			}
		}
		return s.accounts.ListCorpusReleases(ctx, p, q.Get("corpus_id"), after, include, limit)
	})
}
func (s *Server) corpusRelease(w http.ResponseWriter, r *http.Request) {
	corpusGet(s, w, r, s.accounts.CorpusRelease)
}
func (s *Server) deprecateCorpusRelease(w http.ResponseWriter, r *http.Request) {
	corpusPost(s, w, r, func(ctx context.Context, p controlplane.Principal, id, key string, _ struct{}) (controlplane.APIReceipt, error) {
		return s.accounts.DeprecateCorpusRelease(ctx, p, id, key)
	})
}
func (s *Server) agentCorpora(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	if r.Method == "GET" {
		corpusGet(s, w, r, s.accounts.GetAgentCorpora)
		return
	}
	type request struct {
		Corpora []controlplane.CorpusBinding `json:"corpora"`
	}
	corpusPost(s, w, r, func(ctx context.Context, p controlplane.Principal, id, key string, in request) (controlplane.APIReceipt, error) {
		return s.accounts.SetAgentCorpora(ctx, p, id, key, in.Corpora)
	})
}

func (s *Server) corpusEnrichers(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	if r.Method == "POST" {
		corpusPost(s, w, r, func(ctx context.Context, p controlplane.Principal, _, key string, in controlplane.AuthorizeCorpusEnricherInput) (controlplane.APIReceipt, error) {
			return s.accounts.AuthorizeCorpusEnricher(ctx, p, key, in)
		})
		return
	}
	corpusPage(s, w, r, func(e controlplane.CorpusEnricher) string { return e.ID }, s.accounts.ListCorpusEnrichers)
}

func (s *Server) corpusBuildExtensions(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, "GET", "POST") {
		return
	}
	if r.Method == "POST" {
		corpusPost(s, w, r, s.accounts.RequestCorpusExtension)
		return
	}
	corpusGet(s, w, r, func(ctx context.Context, p controlplane.Principal, id string) (map[string]any, error) {
		v, err := s.accounts.BuildExtensions(ctx, p, id)
		return map[string]any{"items": v}, err
	})
}
func (s *Server) corpusExtension(w http.ResponseWriter, r *http.Request) {
	corpusGet(s, w, r, s.accounts.CorpusExtension)
}
