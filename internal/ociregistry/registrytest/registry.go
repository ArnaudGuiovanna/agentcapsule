// Package registrytest is an in-memory OCI distribution registry for tests:
// pull and monolithic push, optional bearer-token authentication, optional
// blob redirection to a second host, and hooks to serve tampered content.
package registrytest

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
)

type Registry struct {
	Server *httptest.Server
	// BlobServer, when set by RedirectBlobs, serves blob downloads.
	BlobServer *httptest.Server
	// Token, when non-empty, is required as a bearer token, issued by /token.
	Token string
	// Tamper may rewrite a blob before it is served (by digest).
	Tamper func(digest string, b []byte) []byte

	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte // repo + "@" + reference
	uploads   map[string]string // upload id -> repo
	next      atomic.Int64
	Pulls     atomic.Int64 // manifest GETs served
}

func New() *Registry {
	r := &Registry{blobs: map[string][]byte{}, manifests: map[string][]byte{}, uploads: map[string]string{}}
	r.Server = httptest.NewServer(http.HandlerFunc(r.serve))
	return r
}

// Host is the registry host:port to put in a policy rule (marked Local).
func (r *Registry) Host() string { return strings.TrimPrefix(r.Server.URL, "http://") }

// RedirectBlobs makes blob GETs answer 307 to a second server, like a CDN.
func (r *Registry) RedirectBlobs() string {
	r.BlobServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.sendBlob(w, strings.TrimPrefix(req.URL.Path, "/blob/"), req.Method == http.MethodHead)
	}))
	return strings.TrimPrefix(r.BlobServer.URL, "http://")
}

func (r *Registry) Close() {
	r.Server.Close()
	if r.BlobServer != nil {
		r.BlobServer.Close()
	}
}

// PutManifest stores raw manifest bytes directly (to serve crafted manifests).
func (r *Registry) PutManifest(repo string, raw []byte) string {
	d := digest(raw)
	r.mu.Lock()
	r.manifests[repo+"@"+d] = raw
	r.mu.Unlock()
	return d
}

func (r *Registry) PutBlob(b []byte) string {
	d := digest(b)
	r.mu.Lock()
	r.blobs[d] = append([]byte(nil), b...)
	r.mu.Unlock()
	return d
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func (r *Registry) serve(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/token" {
		_, _ = io.WriteString(w, `{"token":"`+r.Token+`"}`)
		return
	}
	if r.Token != "" && req.Header.Get("Authorization") != "Bearer "+r.Token {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+r.Server.URL+`/token",service="registrytest",scope="x"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p := strings.TrimPrefix(req.URL.Path, "/v2/")
	switch {
	case strings.HasPrefix(p, "uploads/"):
		r.finishUpload(w, req, strings.TrimPrefix(p, "uploads/"))
	case strings.Contains(p, "/manifests/"):
		i := strings.LastIndex(p, "/manifests/")
		r.manifest(w, req, p[:i], p[i+len("/manifests/"):])
	case strings.HasSuffix(p, "/blobs/uploads/") && req.Method == http.MethodPost:
		id := strings.Repeat("0", 3) + string(rune('a'+r.next.Add(1)%26))
		r.mu.Lock()
		r.uploads[id] = strings.TrimSuffix(p, "/blobs/uploads/")
		r.mu.Unlock()
		w.Header().Set("Location", "/v2/uploads/"+id)
		w.WriteHeader(http.StatusAccepted)
	case strings.Contains(p, "/blobs/"):
		d := p[strings.LastIndex(p, "/blobs/")+len("/blobs/"):]
		if r.BlobServer != nil && req.Method == http.MethodGet {
			http.Redirect(w, req, r.BlobServer.URL+"/blob/"+d, http.StatusTemporaryRedirect)
			return
		}
		r.sendBlob(w, d, req.Method == http.MethodHead)
	default:
		http.NotFound(w, req)
	}
}

func (r *Registry) sendBlob(w http.ResponseWriter, d string, head bool) {
	r.mu.Lock()
	b, ok := r.blobs[d]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	if r.Tamper != nil {
		b = r.Tamper(d, b)
	}
	if head {
		return
	}
	_, _ = w.Write(b)
}

func (r *Registry) manifest(w http.ResponseWriter, req *http.Request, repo, ref string) {
	if req.Method == http.MethodPut {
		raw, _ := io.ReadAll(req.Body)
		d := digest(raw)
		r.mu.Lock()
		r.manifests[repo+"@"+d] = raw
		r.manifests[repo+"@"+ref] = raw
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", d)
		w.WriteHeader(http.StatusCreated)
		return
	}
	r.mu.Lock()
	raw, ok := r.manifests[repo+"@"+ref]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	r.Pulls.Add(1)
	w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	_, _ = w.Write(raw)
}

func (r *Registry) finishUpload(w http.ResponseWriter, req *http.Request, id string) {
	r.mu.Lock()
	_, ok := r.uploads[id]
	delete(r.uploads, id)
	r.mu.Unlock()
	b, _ := io.ReadAll(req.Body)
	if !ok || req.Method != http.MethodPut || digest(b) != req.URL.Query().Get("digest") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.PutBlob(b)
	w.WriteHeader(http.StatusCreated)
}
