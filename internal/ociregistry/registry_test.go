package ociregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/registrytest"
)

func manifestFor(name, version string) harnesspkg.HarnessManifest {
	return harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: name, Version: version, Protocol: harnesspkg.Protocol,
		Architecture: harnesspkg.Architecture, Base: harnesspkg.GuestBase, Entrypoint: []string{"/bin/harness", "--serve"}}
}

// buildPackage makes a real package with mkfs.ext4 -d.
func buildPackage(t *testing.T, m harnesspkg.HarnessManifest) string {
	t.Helper()
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Fatal("mkfs.ext4 (e2fsprogs) is required:", err)
	}
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "bin/harness"), []byte("#!/bin/sh\necho harness\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := harnesspkg.BuildRootfs(t.Context(), m, src, filepath.Join(dir, harnesspkg.RootfsFile), 2); err != nil {
		t.Fatal(err)
	}
	if err := harnesspkg.WritePackage(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir
}

func localRule(reg *registrytest.Registry, repos ...string) Rule {
	return Rule{Host: reg.Host(), Repositories: repos, Local: true}
}

func TestPackageRoundTripThroughARegistryWithTokenAndCDN(t *testing.T) {
	reg := registrytest.New()
	defer reg.Close()
	reg.Token = "pull-token"
	rule := localRule(reg, "acme/")
	rule.BlobHosts = []string{reg.RedirectBlobs()}
	dir := buildPackage(t, manifestFor("echo", "1.0.0"))
	ref, err := Push(t.Context(), rule, "acme/echo", "1.0.0", dir)
	if err != nil {
		t.Fatal(err)
	}
	// Building twice gives the same image: the digest is reproducible.
	again, err := Push(t.Context(), rule, "acme/echo", "", buildPackage(t, manifestFor("echo", "1.0.0")))
	if err != nil || again.Digest != ref.Digest {
		t.Fatal("same inputs produced another digest", again.Digest, ref.Digest, err)
	}
	f, err := NewFetcher(Policy{Rules: []Rule{rule}}, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReference(ref.String())
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	pkg, err := f.Fetch(t.Context(), parsed, out)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Manifest.Name != "echo" || pkg.Manifest.Version != "1.0.0" || pkg.ManifestDigest != ref.Digest || pkg.RootfsSize != 2<<20 {
		t.Fatalf("package %+v", pkg)
	}
	for _, name := range []string{harnesspkg.ManifestFile, harnesspkg.ChecksumsFile, harnesspkg.RootfsFile} {
		st, err := os.Stat(filepath.Join(out, name))
		if err != nil || st.Mode().Perm() != 0o444 {
			t.Fatal("cached file not read-only", name, err)
		}
	}
}

func TestPolicyRefusesUnapprovedAndUnsafeReferences(t *testing.T) {
	reg := registrytest.New()
	defer reg.Close()
	f, err := NewFetcher(Policy{Rules: []Rule{localRule(reg, "acme/")}}, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	digest := "@sha256:" + strings.Repeat("a", 64)
	for _, raw := range []string{
		"acme/echo" + digest,                      // no explicit registry
		reg.Host() + "/acme/echo:1.0",             // not pinned
		reg.Host() + "/acme/echo@sha256:" + "ABC", // malformed digest
		reg.Host() + "/Acme/echo" + digest,        // invalid repository
		reg.Host() + "/other/echo" + digest,       // repository not approved
		"evil.example.com/acme/echo" + digest,     // registry not approved
		"169.254.169.254/acme/echo" + digest,      // metadata address
	} {
		ref, err := ParseReference(raw)
		if err == nil {
			_, err = f.Fetch(t.Context(), ref, t.TempDir())
		}
		if !errors.Is(err, ErrPolicy) {
			t.Fatal("accepted:", raw, err)
		}
	}
	// A public rule never dials a private address, even if DNS says so.
	public := newClient(Rule{Host: "registry.example", Repositories: []string{"x/"}}, 0)
	if _, err := public.http.Get("http://127.0.0.1:1/"); err == nil || !errors.Is(err, ErrPolicy) {
		t.Fatal("public rule dialed loopback", err)
	}
	for _, bad := range []Policy{
		{Rules: []Rule{{Host: "10.0.0.5", Repositories: []string{"x/"}}}},               // address as public rule
		{Rules: []Rule{{Host: "ghcr.io"}}},                                              // no repositories
		{Rules: []Rule{{Host: "ghcr.io", Repositories: []string{"x/"}, Username: "u"}}}, // half credentials
	} {
		if bad.Validate() == nil {
			t.Fatal("unsafe policy accepted", bad)
		}
	}
}

func TestRedirectsAndTokensOnlyToApprovedHosts(t *testing.T) {
	reg := registrytest.New()
	defer reg.Close()
	rule := localRule(reg, "acme/")
	cdn := reg.RedirectBlobs() // not listed in BlobHosts
	dir := buildPackage(t, manifestFor("echo", "1.0.0"))
	ref, err := Push(t.Context(), rule, "acme/echo", "", dir)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := NewFetcher(Policy{Rules: []Rule{rule}}, 64<<20)
	if _, err = f.Fetch(t.Context(), ref, t.TempDir()); !errors.Is(err, ErrPolicy) {
		t.Fatal("blob redirect to an unapproved host followed", cdn, err)
	}
	// A token realm on another host is refused as well.
	if _, err = newClient(rule, 0).fetchToken(t.Context(), "s", `realm="http://attacker.example/token"`); !errors.Is(err, ErrPolicy) {
		t.Fatal("token realm on an unapproved host", err)
	}
}

func TestTamperedOrIncompatiblePackagesAreRejected(t *testing.T) {
	reg := registrytest.New()
	defer reg.Close()
	rule := localRule(reg, "acme/")
	f, _ := NewFetcher(Policy{Rules: []Rule{rule}}, 64<<20)
	good := buildPackage(t, manifestFor("echo", "1.0.0"))
	ref, err := Push(t.Context(), rule, "acme/echo", "", good)
	if err != nil {
		t.Fatal(err)
	}
	// 1. A blob altered in transit.
	reg.Tamper = func(_ string, b []byte) []byte {
		if len(b) > 4096 {
			c := append([]byte(nil), b...)
			c[2000] ^= 1
			return c
		}
		return b
	}
	if _, err = f.Fetch(t.Context(), ref, t.TempDir()); !errors.Is(err, ErrIntegrity) {
		t.Fatal("tampered blob accepted", err)
	}
	reg.Tamper = nil
	// 2. A manifest that does not match the pinned digest.
	wrong := ref
	wrong.Digest = "sha256:" + strings.Repeat("0", 64)
	if _, err = f.Fetch(t.Context(), wrong, t.TempDir()); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown digest", err)
	}
	// 3. Crafted manifests: wrong artifact type, extra layer, oversized rootfs.
	var m imageManifest
	raw := fetchManifest(t, reg, ref)
	for name, mutate := range map[string]func(*imageManifest){
		"artifact type": func(m *imageManifest) { m.ArtifactType = "application/vnd.example" },
		"extra layer":   func(m *imageManifest) { m.Layers = append(m.Layers, m.Layers[0]) },
		"layer order":   func(m *imageManifest) { m.Layers[0], m.Layers[1] = m.Layers[1], m.Layers[0] },
		"too large":     func(m *imageManifest) { m.Layers[2].Size = 1 << 40 },
	} {
		if err = json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		mutate(&m)
		b, _ := json.Marshal(m)
		r := ref
		r.Digest = reg.PutManifest("acme/echo", b)
		if _, err = f.Fetch(t.Context(), r, t.TempDir()); !errors.Is(err, ErrIntegrity) {
			t.Fatal("crafted manifest accepted:", name, err)
		}
	}
	// 4. Incompatible harness.yaml (other architecture), consistent checksums.
	bad := buildPackage(t, manifestFor("echo", "2.0.0"))
	if err = os.WriteFile(filepath.Join(bad, harnesspkg.ManifestFile), []byte(strings.Replace(string(mustRead(t, bad, harnesspkg.ManifestFile)), "x86_64", "aarch64", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	rewriteChecksums(t, bad)
	r2, err := Push(t.Context(), rule, "acme/echo", "", bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Fetch(t.Context(), r2, t.TempDir()); !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "architecture") {
		t.Fatal("incompatible architecture accepted", err)
	}
	// 5. checksums.json that disagrees with the files.
	lying := buildPackage(t, manifestFor("echo", "3.0.0"))
	if err = os.WriteFile(filepath.Join(lying, harnesspkg.ChecksumsFile), []byte(`{"files":{"harness.yaml":"sha256:`+strings.Repeat("1", 64)+`","harness.ext4":"sha256:`+strings.Repeat("2", 64)+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r3, err := Push(t.Context(), rule, "acme/echo", "", lying)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Fetch(t.Context(), r3, t.TempDir()); !errors.Is(err, ErrIntegrity) {
		t.Fatal("lying checksums accepted", err)
	}
	// 6. A rootfs that is not ext4.
	notExt4 := buildPackage(t, manifestFor("echo", "4.0.0"))
	if err = os.WriteFile(filepath.Join(notExt4, harnesspkg.RootfsFile), bytes.Repeat([]byte{7}, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	rewriteChecksums(t, notExt4)
	r4, err := Push(t.Context(), rule, "acme/echo", "", notExt4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Fetch(t.Context(), r4, t.TempDir()); !errors.Is(err, ErrIntegrity) {
		t.Fatal("non-ext4 rootfs accepted", err)
	}
}

func mustRead(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rewriteChecksums(t *testing.T, dir string) {
	t.Helper()
	sums := harnesspkg.Checksums{Files: map[string]string{
		harnesspkg.ManifestFile: harnesspkg.Digest(mustRead(t, dir, harnesspkg.ManifestFile)),
		harnesspkg.RootfsFile:   harnesspkg.Digest(mustRead(t, dir, harnesspkg.RootfsFile))}}
	b, _ := json.Marshal(sums)
	if err := os.WriteFile(filepath.Join(dir, harnesspkg.ChecksumsFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fetchManifest(t *testing.T, reg *registrytest.Registry, ref Reference) []byte {
	t.Helper()
	c := newClient(Rule{Host: reg.Host(), Repositories: []string{"acme/"}, Local: true}, 0)
	resp, err := c.http.Get(c.base() + "/v2/" + ref.Repository + "/manifests/" + ref.Digest)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return buf.Bytes()
}

// Use a layer larger than the upload chunk so the publishing path, including
// the final digest after PATCH, is exercised by a real loopback HTTP registry.
func TestChunkedLayerMatchesOfflinePackageDigest(t *testing.T) {
	reg := registrytest.New()
	defer reg.Close()
	dir := buildPackage(t, manifestFor("chunked", "1"))
	f, err := os.OpenFile(filepath.Join(dir, harnesspkg.RootfsFile), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(uploadChunk*2 + 521); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	expected, err := PackageDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := Push(t.Context(), localRule(reg, "acme/test"), "acme/test", "1", dir)
	if err != nil || ref.Digest != expected {
		t.Fatalf("digest=%s, pushed=%s, err=%v", expected, ref.Digest, err)
	}
}

func TestChunkedUploadRecoversCommittedBytesAndRotatedSession(t *testing.T) {
	data := bytes.Repeat([]byte("a long layer"), uploadChunk/6+1)
	digest := sha256Hex(data)
	var mu sync.Mutex
	var written int64
	h := sha256.New()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodHead:
			http.NotFound(w, r)
		case http.MethodPost:
			w.Header().Set("Location", "/session")
			w.WriteHeader(http.StatusAccepted)
		case http.MethodGet:
			w.Header().Set("Range", fmt.Sprintf("0-%d", written-1))
			w.Header().Set("Location", "/resume")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPatch:
			if written == 0 {
				// The registry has persisted a prefix before reporting an error.
				var err error
				written, err = io.CopyN(h, r.Body, 4096)
				if err != nil {
					t.Error(err)
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if r.URL.Path != "/resume" || r.Header.Get("Content-Range") != fmt.Sprintf("%d-%d", written, written+r.ContentLength-1) {
				t.Error("incorrect resume point", r.URL.Path, r.Header.Get("Content-Range"))
			}
			n, err := io.Copy(h, r.Body)
			if err != nil {
				t.Error(err)
			}
			written += n
			w.Header().Set("Location", "/resume")
			w.Header().Set("Range", fmt.Sprintf("0-%d", written-1))
			w.WriteHeader(http.StatusAccepted)
		case http.MethodPut:
			if r.URL.Path != "/resume" || r.ContentLength != 0 || r.URL.Query().Get("digest") != digest || fmt.Sprintf("sha256:%x", h.Sum(nil)) != digest {
				t.Error("incorrect committed layer", written, r.ContentLength)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Error("unexpected method", r.Method)
			http.NotFound(w, r)
		}
	}))
	defer reg.Close()
	c := newClient(Rule{Host: strings.TrimPrefix(reg.URL, "http://"), Local: true}, 0)
	if err := c.upload(t.Context(), "acme/test", "repository:acme/test:pull,push", digest, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
}

func TestUnavailableUploadStatusReplaysOnlyTheSameRange(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("followed upload-status redirect off the registry")
	}))
	defer web.Close()
	var mu sync.Mutex
	attempts := 0
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			http.Redirect(w, r, web.URL+"/status", http.StatusFound)
			return
		}
		payload, err := io.ReadAll(r.Body)
		if r.Method != http.MethodPatch || string(payload) != "chunk" || err != nil || r.Header.Get("Content-Range") != "0-4" {
			t.Error("replayed a different chunk or range")
		}
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Location", "/next")
		w.Header().Set("Range", "0-4")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer reg.Close()
	c := newClient(Rule{Host: strings.TrimPrefix(reg.URL, "http://"), Local: true}, 0)
	loc, err := url.Parse(reg.URL + "/session")
	if err != nil {
		t.Fatal(err)
	}
	next, offset, err := c.sendChunk(t.Context(), "acme/test", "repository:acme/test:pull,push", loc, strings.NewReader("chunk"), 0, 5)
	if err != nil || offset != 5 || next.Path != "/next" {
		t.Fatal("status fallback", offset, err)
	}
}
