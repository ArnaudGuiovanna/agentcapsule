// Package registrytest is an in-memory OCI distribution registry for tests:
// pull and monolithic push, optional bearer-token or Basic authentication,
// optional blob redirection to a second host, hooks to serve tampered content,
// and counters that reveal credentials sent where they should not go.
package registrytest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	// Username and Password, when set with Token, make the registry private:
	// /token issues Token only for these Basic credentials, refuses wrong
	// ones (401) and gives anonymous callers a token the registry rejects.
	// With Basic, the registry itself requires them (no token service).
	Username, Password string
	Basic              bool
	// NoReferrers makes the registry lack the OCI referrers API, like GHCR:
	// clients must use the referrers tag schema instead.
	NoReferrers bool
	// BasicSeen counts registry API requests carrying Basic credentials while
	// a token service is in use; BlobAuth counts blob-host requests carrying
	// any Authorization header. Both must stay zero. Challenges counts 401
	// challenges the registry API answered.
	BasicSeen, BlobAuth, Challenges atomic.Int64
	// BlobPulls counts blob GETs served (by the registry or its blob host).
	BlobPulls atomic.Int64
	// Tamper may rewrite a blob before it is served (by digest).
	Tamper func(digest string, b []byte) []byte

	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte // repo + "@" + reference
	types     map[string]string // repo + "@" + reference -> media type
	uploads   map[string]string // upload id -> repo
	next      atomic.Int64
	Pulls     atomic.Int64 // manifest GETs served
}

func New() *Registry {
	r := &Registry{blobs: map[string][]byte{}, manifests: map[string][]byte{}, types: map[string]string{}, uploads: map[string]string{}}
	r.Server = httptest.NewServer(http.HandlerFunc(r.serve))
	return r
}

// Host is the registry host:port to put in a policy rule (marked Local).
func (r *Registry) Host() string { return strings.TrimPrefix(r.Server.URL, "http://") }

// RedirectBlobs makes blob GETs answer 307 to a second server, like a CDN.
func (r *Registry) RedirectBlobs() string {
	r.BlobServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "" {
			r.BlobAuth.Add(1)
		}
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

// PutManifestAs stores raw bytes under a tag with a media type (to serve
// crafted indexes).
func (r *Registry) PutManifestAs(repo, tag string, raw []byte, mediaType string) {
	r.mu.Lock()
	r.manifests[repo+"@"+tag] = raw
	r.types[repo+"@"+tag] = mediaType
	r.mu.Unlock()
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
	user, password, hasBasic := req.BasicAuth()
	matches := hasBasic && user == r.Username && password == r.Password
	if req.URL.Path == "/token" {
		token := r.Token
		switch {
		case r.Username == "":
		case !hasBasic:
			token = "anonymous"
		case !matches:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"token":"`+token+`"}`)
		return
	}
	switch {
	case r.Basic:
		if !matches {
			r.Challenges.Add(1)
			w.Header().Set("WWW-Authenticate", `Basic realm="registrytest"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	case r.Token != "":
		if hasBasic {
			r.BasicSeen.Add(1)
		}
		if req.Header.Get("Authorization") != "Bearer "+r.Token {
			r.Challenges.Add(1)
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+r.Server.URL+`/token",service="registrytest",scope="x"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	p := strings.TrimPrefix(req.URL.Path, "/v2/")
	switch {
	case strings.Contains(p, "/referrers/") && req.Method == http.MethodGet:
		i := strings.LastIndex(p, "/referrers/")
		r.referrers(w, p[:i], p[i+len("/referrers/"):])
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
	if !head {
		r.BlobPulls.Add(1)
	}
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
		mt := req.Header.Get("Content-Type")
		r.mu.Lock()
		r.manifests[repo+"@"+d] = raw
		r.manifests[repo+"@"+ref] = raw
		r.types[repo+"@"+d], r.types[repo+"@"+ref] = mt, mt
		r.mu.Unlock()
		var m struct {
			Subject *struct {
				Digest string `json:"digest"`
			} `json:"subject"`
		}
		if !r.NoReferrers && json.Unmarshal(raw, &m) == nil && m.Subject != nil {
			w.Header().Set("OCI-Subject", m.Subject.Digest)
		}
		w.Header().Set("Docker-Content-Digest", d)
		w.WriteHeader(http.StatusCreated)
		return
	}
	r.mu.Lock()
	raw, ok := r.manifests[repo+"@"+ref]
	mt := r.types[repo+"@"+ref]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	if mt == "" {
		mt = "application/vnd.oci.image.manifest.v1+json"
	}
	r.Pulls.Add(1)
	w.Header().Set("Content-Type", mt)
	_, _ = w.Write(raw)
}

// referrers answers the OCI referrers API from the stored manifests whose
// subject is subject, unless NoReferrers.
func (r *Registry) referrers(w http.ResponseWriter, repo, subject string) {
	if r.NoReferrers {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	type desc struct {
		MediaType    string            `json:"mediaType"`
		ArtifactType string            `json:"artifactType,omitempty"`
		Digest       string            `json:"digest"`
		Size         int               `json:"size"`
		Annotations  map[string]string `json:"annotations,omitempty"`
	}
	index := struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []desc `json:"manifests"`
	}{2, "application/vnd.oci.image.index.v1+json", []desc{}}
	r.mu.Lock()
	for key, raw := range r.manifests {
		if !strings.HasPrefix(key, repo+"@sha256:") || strings.TrimPrefix(key, repo+"@") != digest(raw) {
			continue
		}
		var m struct {
			ArtifactType string `json:"artifactType"`
			Config       struct {
				MediaType string `json:"mediaType"`
			} `json:"config"`
			Subject *struct {
				Digest string `json:"digest"`
			} `json:"subject"`
			Annotations map[string]string `json:"annotations"`
		}
		if json.Unmarshal(raw, &m) != nil || m.Subject == nil || m.Subject.Digest != subject {
			continue
		}
		artifact := m.ArtifactType
		if artifact == "" {
			artifact = m.Config.MediaType
		}
		index.Manifests = append(index.Manifests, desc{MediaType: r.types[key], ArtifactType: artifact, Digest: digest(raw), Size: len(raw), Annotations: m.Annotations})
	}
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
	_ = json.NewEncoder(w).Encode(index)
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
