// Package forgetest is a fake Git forge for tests: the parts of the GitHub
// and GitLab APIs, archive hosts and LFS batch API that corpus sources use,
// on one TLS server whose certificate names every fake host, behind a fake
// DNS. It records each request it serves, and can misbehave on demand: alter
// an LFS object, redirect an archive to an undeclared host, send an encoded
// archive, or cut a download in the middle. Only tests import it.
package forgetest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
)

// The fake hosts.
const (
	GitHubHost   = "github.test"
	GitHubAPI    = "api.github.test"
	Codeload     = "codeload.github.test"
	GitHubLFS    = "lfs.github.test"
	GitLabHost   = "gitlab.test"
	Elsewhere    = "elsewhere.test"
	publicAddr   = "8.8.8.8"
	signatureKey = "forgetest-signing-key"
)

// Repo is a repository of the fake forge. A private one answers only to
// Token, as the forges do: 404 to the API without it, 401 to the LFS API.
type Repo struct {
	Kind    string
	Path    string
	Private bool
	Token   string
	// Refs maps a branch or tag to its commit; a commit names itself.
	Refs map[string]string
	// Archives maps a commit to its archive's bytes.
	Archives map[string][]byte
	// Objects maps an oid to the LFS object's bytes.
	Objects map[string][]byte
}

// Request is one request the forge served.
type Request struct {
	Host, Method, Path, Query string
	Authorization             string
}

// Forge is the fake forge.
type Forge struct {
	srv   *httptest.Server
	roots *x509.CertPool

	mu    sync.Mutex
	repos map[string]*Repo
	names map[string][]netip.Addr
	log   []Request
	// Tampered serves altered bytes for these oids.
	Tampered map[string]bool
	// ArchiveRedirect, when set, is the host GitHub's archive redirect
	// names instead of the archive host.
	ArchiveRedirect string
	// ArchiveEncoding, when set, is the Content-Encoding of archives.
	ArchiveEncoding string
	// Chunked sends archives without a Content-Length.
	Chunked bool
	// SignedURLs makes the batch API give download URLs that carry their
	// own signature, and no header: GitHub's from its LFS host, GitLab's
	// from the forge itself, which then takes the repository's credential.
	SignedURLs bool
	// Cut is how many more times each oid's download stops in the middle.
	Cut map[string]int
	// Dialed lists the addresses connected to.
	Dialed []string
}

// New starts a fake forge, stopped with the test.
func New(t testing.TB) *Forge {
	t.Helper()
	f := &Forge{repos: map[string]*Repo{}, names: map[string][]netip.Addr{}, Tampered: map[string]bool{}, Cut: map[string]int{}}
	cert, roots := certificate(t, GitHubHost, GitHubAPI, Codeload, GitHubLFS, GitLabHost, Elsewhere, "gitlab.internal")
	f.roots = roots
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	for _, h := range []string{GitHubHost, GitHubAPI, Codeload, GitHubLFS, GitLabHost, Elsewhere} {
		f.Resolve(h, publicAddr)
	}
	return f
}

// certificate makes a self-signed certificate for the names.
func certificate(t testing.TB, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "forgetest"}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// Add puts a repository on the forge.
func (f *Forge) Add(r *Repo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.repos[r.Kind+":"+strings.ToLower(r.Path)] = r
}

// Resolve makes a name resolve to the addresses.
func (f *Forge) Resolve(name string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.names[name] = nil
	for _, a := range addrs {
		f.names[name] = append(f.names[name], netip.MustParseAddr(a))
	}
}

// Network is the fake DNS and network: every connection reaches the forge's
// server, whatever address it was for, and is recorded.
func (f *Forge) Network() corpussource.TestNetwork {
	return corpussource.TestNetwork{RootCAs: f.roots,
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if a, ok := f.names[host]; ok {
				return a, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
		Connect: func(ctx context.Context, network, address string) (net.Conn, error) {
			f.mu.Lock()
			f.Dialed = append(f.Dialed, address)
			f.mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, f.srv.Listener.Addr().String())
		},
	}
}

// Rules are a GitHub rule for acme/ and a GitLab rule for school/, with the
// forge's archive and LFS hosts.
func Rules() []corpussource.Rule {
	return []corpussource.Rule{
		{Host: GitHubHost, Kind: corpussource.GitHub, APIHost: GitHubAPI, Repositories: []string{"acme/"},
			ArchiveHosts: []string{Codeload}, LFSHosts: []string{GitHubLFS}},
		{Host: GitLabHost, Kind: corpussource.GitLab, Repositories: []string{"school/"}},
	}
}

// Requests returns the requests served so far.
func (f *Forge) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.log...)
}

// Reset forgets the requests served and the addresses dialed.
func (f *Forge) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log, f.Dialed = nil, nil
}

// OID is the oid of an object's bytes.
func OID(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sign(parts ...string) string {
	m := hmac.New(sha256.New, []byte(signatureKey))
	m.Write([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(m.Sum(nil))
}

func (f *Forge) repo(kind, path string) *Repo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.repos[kind+":"+strings.ToLower(path)]
}

func (f *Forge) serve(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	f.mu.Lock()
	f.log = append(f.log, Request{Host: host, Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Authorization: r.Header.Get("Authorization")})
	f.mu.Unlock()
	path := r.URL.EscapedPath()
	switch {
	case host == GitHubAPI && strings.HasPrefix(path, "/repos/"):
		f.githubAPI(w, r, strings.TrimPrefix(path, "/repos/"))
	case host == Codeload || host == Elsewhere:
		f.codeload(w, r, path)
	case host == GitHubLFS:
		f.githubObject(w, r, path)
	case host == GitLabHost && strings.HasPrefix(path, "/api/v4/projects/"):
		f.gitlabAPI(w, r, strings.TrimPrefix(path, "/api/v4/projects/"))
	case (host == GitHubHost || host == GitLabHost) && strings.HasSuffix(path, ".git/info/lfs/objects/batch") && r.Method == http.MethodPost:
		f.batch(w, r, host, strings.TrimSuffix(strings.TrimPrefix(path, "/"), ".git/info/lfs/objects/batch"))
	case host == GitLabHost && strings.Contains(path, ".git/gitlab-lfs/objects/"):
		f.gitlabObject(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

func bearerOK(r *http.Request, repo *Repo) bool {
	return !repo.Private || r.Header.Get("Authorization") == "Bearer "+repo.Token
}

func basicOK(r *http.Request, repo *Repo) bool {
	_, password, ok := r.BasicAuth()
	return !repo.Private || ok && password == repo.Token
}

func (f *Forge) githubAPI(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.SplitN(rest, "/", 4)
	if len(parts) != 4 {
		http.NotFound(w, r)
		return
	}
	repo := f.repo(corpussource.GitHub, parts[0]+"/"+parts[1])
	if repo == nil || !bearerOK(r, repo) {
		http.NotFound(w, r)
		return
	}
	switch parts[2] {
	case "commits":
		ref, _ := url.PathUnescape(parts[3])
		commit, ok := repo.Refs[ref]
		if !ok {
			http.Error(w, `{"message":"No commit found for SHA"}`, http.StatusUnprocessableEntity)
			return
		}
		if r.Header.Get("Accept") == "application/vnd.github.sha" {
			_, _ = w.Write([]byte(commit))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": commit, "files": []any{}})
	case "tarball":
		commit := parts[3]
		if _, ok := repo.Archives[commit]; !ok {
			http.NotFound(w, r)
			return
		}
		to := Codeload
		f.mu.Lock()
		if f.ArchiveRedirect != "" {
			to = f.ArchiveRedirect
		}
		f.mu.Unlock()
		q := ""
		if repo.Private {
			q = "?token=" + sign(repo.Path, commit)
		}
		http.Redirect(w, r, "https://"+to+"/"+repo.Path+"/legacy.tar.gz/"+commit+q, http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func (f *Forge) codeload(w http.ResponseWriter, r *http.Request, path string) {
	before, commit, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/legacy.tar.gz/")
	repo := f.repo(corpussource.GitHub, before)
	if !ok || repo == nil || repo.Private && r.URL.Query().Get("token") != sign(repo.Path, commit) {
		http.NotFound(w, r)
		return
	}
	f.archive(w, r, repo, commit)
}

func (f *Forge) archive(w http.ResponseWriter, r *http.Request, repo *Repo, commit string) {
	body, ok := repo.Archives[commit]
	if !ok {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	encoding, chunked := f.ArchiveEncoding, f.Chunked
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-gzip")
	if encoding != "" {
		w.Header().Set("Content-Encoding", encoding)
	}
	if chunked {
		_, _ = w.Write(body[:len(body)/2])
		w.(http.Flusher).Flush()
		_, _ = w.Write(body[len(body)/2:])
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func (f *Forge) gitlabAPI(w http.ResponseWriter, r *http.Request, rest string) {
	encoded, tail, ok := strings.Cut(rest, "/repository/")
	path, err := url.PathUnescape(encoded)
	if !ok || err != nil || strings.Contains(encoded, "/") {
		http.NotFound(w, r)
		return
	}
	repo := f.repo(corpussource.GitLab, path)
	if repo == nil || !bearerOK(r, repo) {
		http.Error(w, `{"message":"404 Project Not Found"}`, http.StatusNotFound)
		return
	}
	switch {
	case strings.HasPrefix(tail, "commits/"):
		ref, _ := url.PathUnescape(strings.TrimPrefix(tail, "commits/"))
		commit, ok := repo.Refs[ref]
		if !ok {
			http.Error(w, `{"message":"404 Commit Not Found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": commit, "short_id": commit[:8], "title": "a commit"})
	case tail == "archive.tar.gz":
		f.archive(w, r, repo, r.URL.Query().Get("sha"))
	default:
		http.NotFound(w, r)
	}
}

func (f *Forge) batch(w http.ResponseWriter, r *http.Request, host, path string) {
	kind := corpussource.GitHub
	if host == GitLabHost {
		kind = corpussource.GitLab
	}
	repo := f.repo(kind, path)
	if repo == nil {
		http.NotFound(w, r)
		return
	}
	if !basicOK(r, repo) {
		w.Header().Set("LFS-Authenticate", `Basic realm="Git LFS"`)
		http.Error(w, `{"message":"Credentials needed"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Operation string `json:"operation"`
		Objects   []struct {
			OID  string `json:"oid"`
			Size int64  `json:"size"`
		} `json:"objects"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Operation != "download" || len(req.Objects) > 100 {
		http.Error(w, "bad batch", http.StatusUnprocessableEntity)
		return
	}
	var out []map[string]any
	for _, o := range req.Objects {
		body, ok := repo.Objects[o.OID]
		if !ok {
			out = append(out, map[string]any{"oid": o.OID, "size": o.Size, "error": map[string]any{"code": 404, "message": "Object does not exist"}})
			continue
		}
		href := "https://" + GitHubLFS + "/objects/" + o.OID
		header := map[string]string{"Authorization": "RemoteAuth " + sign(o.OID)}
		if kind == corpussource.GitLab {
			href = "https://" + GitLabHost + "/" + repo.Path + ".git/gitlab-lfs/objects/" + o.OID
			header = map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("lfs:"+sign(o.OID)))}
		}
		f.mu.Lock()
		signed := f.SignedURLs
		f.mu.Unlock()
		download := map[string]any{"href": href, "header": header, "expires_in": 3600}
		if signed {
			download = map[string]any{"href": href + "?sig=" + sign(o.OID), "expires_in": 3600}
		}
		out = append(out, map[string]any{"oid": o.OID, "size": len(body), "authenticated": true, "actions": map[string]any{"download": download}})
	}
	w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
	_ = json.NewEncoder(w).Encode(map[string]any{"transfer": "basic", "objects": out})
}

func (f *Forge) githubObject(w http.ResponseWriter, r *http.Request, path string) {
	oid := strings.TrimPrefix(path, "/objects/")
	if r.Header.Get("Authorization") != "RemoteAuth "+sign(oid) && r.URL.Query().Get("sig") != sign(oid) {
		http.Error(w, "unsigned", http.StatusForbidden)
		return
	}
	f.object(w, r, oid)
}

func (f *Forge) gitlabObject(w http.ResponseWriter, r *http.Request, path string) {
	before, oid, _ := strings.Cut(path, ".git/gitlab-lfs/objects/")
	repo := f.repo(corpussource.GitLab, strings.TrimPrefix(before, "/"))
	signed := r.URL.Query().Get("sig") == sign(oid) && repo != nil && repo.Private && basicOK(r, repo)
	if !signed && r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("lfs:"+sign(oid))) {
		http.Error(w, "unsigned", http.StatusUnauthorized)
		return
	}
	f.object(w, r, oid)
}

func (f *Forge) object(w http.ResponseWriter, r *http.Request, oid string) {
	var body []byte
	f.mu.Lock()
	for _, repo := range f.repos {
		if b, ok := repo.Objects[oid]; ok {
			body = b
		}
	}
	tampered, cut := f.Tampered[oid], f.Cut[oid] > 0
	if cut {
		f.Cut[oid]--
	}
	f.mu.Unlock()
	if body == nil {
		http.NotFound(w, r)
		return
	}
	if tampered {
		body = append([]byte(nil), body...)
		body[0] ^= 0xff
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if cut {
		_, _ = w.Write(body[:len(body)/2])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	_, _ = w.Write(body)
}
