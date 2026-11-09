package ociregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		if err != nil || st.Mode().Perm() != 0o400 {
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
	if err = newClient(rule, 0).fetchToken(t.Context(), "acme/echo", "s", `Bearer realm="http://attacker.example/token"`); !errors.Is(err, ErrPolicy) {
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
