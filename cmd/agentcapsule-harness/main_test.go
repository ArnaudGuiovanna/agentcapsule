package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/registrytest"
)

// capture runs the CLI and returns what it printed.
func capture(t *testing.T, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	runErr := run(args)
	os.Stdout = stdout
	w.Close()
	var out bytes.Buffer
	_, _ = io.Copy(&out, r)
	if runErr != nil {
		t.Fatal(args[0], runErr)
	}
	return strings.TrimSpace(out.String())
}

// A publisher packs, pushes and signs a harness with the CLI; a platform that
// trusts the generated public key imports it, and knows who signed it.
func TestPublisherSignsWhatThePlatformImports(t *testing.T) {
	reg := registrytest.New()
	defer reg.Close()
	reg.NoReferrers = true // like GHCR: the referrers tag schema is used
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rootfs/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rootfs/bin/harness"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: agentcapsule.harness/v1\nname: echo\nversion: 1.0.0\nprotocol: capsule.v1\narchitecture: x86_64\nbase: agentcapsule-guest/1\nentrypoint: [/bin/harness]\n"
	if err := os.WriteFile(filepath.Join(dir, "harness.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	capture(t, "pack", "--manifest", filepath.Join(dir, "harness.yaml"), "--rootfs", filepath.Join(dir, "rootfs"), "--size-mib", "2", "--out", filepath.Join(dir, "package"))
	ref := capture(t, "push", "--dir", filepath.Join(dir, "package"), "--registry", reg.Host(), "--repository", "acme/echo", "--tag", "1.0.0", "--local")
	capture(t, "keygen", "--out", filepath.Join(dir, "publisher"))
	if st, err := os.Stat(filepath.Join(dir, "publisher.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("private key not private", err)
	}
	if err := run([]string{"keygen", "--out", filepath.Join(dir, "publisher")}); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	capture(t, "sign", "--key", filepath.Join(dir, "publisher.key"), "--ref", ref, "--local")

	// The publisher checks what the platform will see before handing it over.
	report := capture(t, "verify", "--ref", ref, "--key", filepath.Join(dir, "publisher.pub"), "--local")
	if !strings.Contains(report, `"signer": "sha256:`) || !strings.Contains(report, `"name": "echo"`) {
		t.Fatal("verify did not report the signed package", report)
	}
	if err := run([]string{"verify", "--ref", ref, "--key", filepath.Join(dir, "other.pub"), "--local"}); err == nil {
		t.Fatal("verify accepted a missing key file")
	}

	pub, err := os.ReadFile(filepath.Join(dir, "publisher.pub"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ociregistry.ParsePublisherKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ociregistry.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ociregistry.NewFetcher(ociregistry.Policy{RequireSignatures: true, Rules: []ociregistry.Rule{
		{Host: reg.Host(), Repositories: []string{"acme/"}, Local: true, Keys: []ociregistry.PublisherKey{key}}}}, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := f.Fetch(t.Context(), parsed, t.TempDir())
	if err != nil || pkg.Signer != key.ID {
		t.Fatal("the platform did not accept the publisher's signature", err)
	}
}
