//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// A host rebuilt from its backups keeps its releases in PostgreSQL, each with
// the digest of its package, but not its harness cache (OPR-10). An agent on
// an imported harness is archived; the cache is lost; the worker fetches the
// package again by the digest its release recorded; the agent is restored
// from its archive, boots the image fetched again and answers.
func TestProductWorkerRefetchesTheHarnessOfARestoredAgent(t *testing.T) {
	l := newRegistryLab(t)
	ref := l.publish("1.0.0", "opt/echo")
	agent := l.create("refetched", "1.0.0").AgentID
	l.answers(agent, "before-archive", "written before the archive")
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "archives"))
	if err != nil {
		t.Fatal(err)
	}
	archiveID := "arc_" + strings.Repeat("9", 32)
	if _, err = l.worker.CaptureArchive(t.Context(), agent, archiveID, archives); err != nil {
		t.Fatal(err)
	}
	l.runs(0)

	t.Log("stage: the harness cache is lost; PostgreSQL keeps the release and its digest")
	var releases struct {
		Items []controlplane.HarnessRelease `json:"items"`
	}
	l.request(l.platform, "GET", "/v1/harness-releases", "", nil, 200, &releases)
	var release controlplane.HarnessRelease
	for _, r := range releases.Items {
		if r.Name == "echo-oci" && r.Version == "1.0.0" {
			release = r
		}
	}
	if release.Digest != ref.Digest || !strings.HasSuffix(release.Reference, "@"+ref.Digest) || release.RootfsDigest == "" {
		t.Fatal("the release does not record its package's digest", release)
	}
	dir := l.importer.PackageDir(ref.Digest)
	if err = removeTree(dir); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the cache still holds the package", err)
	}

	t.Log("stage: the worker fetches the package again by its digest")
	got, err := l.importer.Refill(t.Context())
	if err != nil || len(got) != 1 || got[0] != ref.Digest {
		t.Fatal("refill", got, err)
	}
	image, err := os.ReadFile(filepath.Join(dir, harnesspkg.RootfsFile))
	if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(image)) != release.RootfsDigest {
		t.Fatal("the image fetched again is not the release's", err)
	}

	t.Log("stage: the agent is restored from its archive, boots the image fetched again and answers")
	if _, err = l.worker.RestoreFromArchive(t.Context(), "rst_"+strings.Repeat("9", 32), agent, archiveID, archives,
		func(err error) { t.Error("the restore paused", err) }); err != nil {
		t.Fatal("restore", err)
	}
	l.answers(agent, "after-restore", "answered from the image fetched again")
	l.bootsFrom(agent, ref, 1)
}
