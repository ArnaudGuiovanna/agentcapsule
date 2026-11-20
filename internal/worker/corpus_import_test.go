//go:build linux

package worker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
)

// An import records the guest base harness.yaml names: only a release of
// base 2 has the /corpus mount point (ADR 023 §5.4).
func TestAnImportRecordsTheHarnessBase(t *testing.T) {
	l := newImportLab(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "harness"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{harnesspkg.GuestBase, harnesspkg.GuestBase2} {
		m := harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: "echo", Version: base[len(base)-1:] + ".0.0", Protocol: harnesspkg.Protocol,
			Architecture: harnesspkg.Architecture, Base: base, Entrypoint: []string{"/harness"}}
		dir := t.TempDir()
		if err := harnesspkg.BuildRootfs(t.Context(), m, src, filepath.Join(dir, harnesspkg.RootfsFile), 1); err != nil {
			t.Fatal(err)
		}
		if err := harnesspkg.WritePackage(dir, m); err != nil {
			t.Fatal(err)
		}
		ref, err := ociregistry.Push(t.Context(), l.rule, "acme/echo", m.Version, dir)
		if err != nil {
			t.Fatal(err)
		}
		imp := l.request(t, "import-"+m.Version, ref.String())
		l.importOne(t)
		done := l.state(t, imp.ID)
		if done.State != "READY" {
			t.Fatal("import", done)
		}
		releases, err := l.accounts.ListHarnessReleases(t.Context(), l.platform, true)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range releases {
			if r.ID == done.ReleaseID {
				found = true
				if r.Base != base {
					t.Fatal("the release's base", r.Base, base)
				}
			}
		}
		if !found {
			t.Fatal("release not listed", done.ReleaseID)
		}
	}
}
