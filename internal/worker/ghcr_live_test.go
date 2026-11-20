//go:build linux && ghcrlive

package worker

// Live imports from GHCR (REG-002: the same test passes on GHCR and on a
// local registry). Opt-in: only built with -tags ghcrlive, so that CI and the
// PostgreSQL campaign stay offline. PostgreSQL is required as for the
// local-registry test. AGENTCAPSULE_TEST_GHCR_REFERENCE names a
// harness package pinned by digest, ghcr.io/<owner>/<name>[:tag]@sha256:...
// For a private package, AGENTCAPSULE_TEST_GHCR_USERNAME and
// AGENTCAPSULE_REGISTRY_PASSWORD supply registry credentials. With
// AGENTCAPSULE_TEST_GHCR_PUBLISHER_KEY, imports must verify that publisher's
// signature. AGENTCAPSULE_TEST_GHCR_EXPORT optionally keeps the verified
// package for a subsequent KVM run of exactly the same bytes.

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// ghcrImporter replaces the lab's importer by one whose policy approves the
// repositories of owner on GHCR, with GitHub's blob CDN.
func ghcrImporter(t *testing.T, l *importLab, owner string) {
	t.Helper()
	rule := ociregistry.Rule{Host: "ghcr.io", Repositories: []string{owner + "/"}, BlobHosts: []string{"pkg-containers.githubusercontent.com"}}
	rule.Username = os.Getenv("AGENTCAPSULE_TEST_GHCR_USERNAME")
	rule.Password = os.Getenv("AGENTCAPSULE_REGISTRY_PASSWORD")
	if path := os.Getenv("AGENTCAPSULE_TEST_GHCR_PUBLISHER_KEY"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ociregistry.ParsePublisherKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		rule.Keys = []ociregistry.PublisherKey{key}
	}
	fetcher, err := ociregistry.NewFetcher(ociregistry.Policy{Rules: []ociregistry.Rule{rule}}, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		fetcher.Sandbox = sandbox.Options{UID: 61999, GID: 61999}
	}
	if l.importer, err = NewHarnessImporter(l.store, fetcher, l.cache, "importer-ghcr"); err != nil {
		t.Fatal(err)
	}
}

// The assertions of TestWorkerImportsVerifiedPackagesIntoTheCache, on a
// package served by GHCR: the import is READY with a release, the cached
// files are read-only, nothing is left to do or in staging.
func TestLiveGHCRImport(t *testing.T) {
	reference := os.Getenv("AGENTCAPSULE_TEST_GHCR_REFERENCE")
	ref, err := ociregistry.ParseReference(reference)
	if err != nil || ref.Registry != "ghcr.io" {
		t.Fatal("-tags ghcrlive needs AGENTCAPSULE_TEST_GHCR_REFERENCE=ghcr.io/<owner>/<name>@sha256:<digest>", err)
	}
	l := newImportLab(t)
	ghcrImporter(t, l, strings.SplitN(ref.Repository, "/", 2)[0])
	imp := l.request(t, "ghcr", ref.String())
	l.importOne(t)
	done := l.state(t, imp.ID)
	if done.State != "READY" || done.ReleaseID == "" {
		t.Fatal("import", done)
	}
	dir := l.importer.PackageDir(ref.Digest)
	for _, name := range []string{harnesspkg.ManifestFile, harnesspkg.ChecksumsFile, harnesspkg.RootfsFile} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm()&0o222 != 0 {
			t.Fatal("cached file missing or writable", name, err)
		}
	}
	if worked, err := l.importer.ImportOne(t.Context()); err != nil || worked {
		t.Fatal("work left", worked, err)
	}
	if dest := os.Getenv("AGENTCAPSULE_TEST_GHCR_EXPORT"); dest != "" {
		if err := os.Mkdir(dest, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{harnesspkg.ManifestFile, harnesspkg.ChecksumsFile, harnesspkg.RootfsFile} {
			src, err := os.Open(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			out, err := os.OpenFile(filepath.Join(dest, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
			if err != nil {
				src.Close()
				t.Fatal(err)
			}
			_, copyErr := io.Copy(out, src)
			src.Close()
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil {
				t.Fatal("export verified package", copyErr, closeErr)
			}
		}
	}
}

// slimImage is a public image on GHCR that is not a harness package: the
// linux/amd64 manifest of the SLIM node the interoperability services pin
// (deploy/interop/compose.yml pins its index, which GHCR does not serve to a
// request that accepts only an image manifest: not_found).
const slimImage = "ghcr.io/agntcy/slim:3.4.6@sha256:033ff72940e687d790a127fb6d3efb3956700f3626f095a3a7fd4fb7c244b037"

// GHCR's anonymous token exchange works, and an image that is not a harness
// package is rejected at its manifest, before any layer is downloaded.
func TestLiveGHCRRejectsAnImageThatIsNotAHarness(t *testing.T) {
	// This control deliberately checks anonymous access to the foreign image,
	// independently of the publisher and credentials of the positive test.
	t.Setenv("AGENTCAPSULE_TEST_GHCR_USERNAME", "")
	t.Setenv("AGENTCAPSULE_REGISTRY_PASSWORD", "")
	t.Setenv("AGENTCAPSULE_TEST_GHCR_PUBLISHER_KEY", "")
	l := newImportLab(t)
	ghcrImporter(t, l, "agntcy")
	imp := l.request(t, "slim", slimImage)
	l.importOne(t)
	if v := l.state(t, imp.ID); v.State != "REJECTED" || v.ErrorCode != "integrity" || v.Attempts != 1 {
		t.Fatal("a foreign image", v)
	}
	if entries, err := os.ReadDir(filepath.Join(l.cache, "sha256")); err != nil || len(entries) != 0 {
		t.Fatal("a foreign image reached the cache", len(entries), err)
	}
}
