package controlplane

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func approvedImages(t *testing.T, c *AgentCatalog, p Principal) map[string]SystemImage {
	t.Helper()
	items, err := c.SystemImages(t.Context(), p, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]SystemImage{}
	for _, i := range items {
		out[i.ID] = i
	}
	return out
}

// A system image declares, at its approval, what its capsule-init can do
// beyond the base guest: corpus.mount, from a closed list (ADR 023 §5.5).
// An approval is immutable, its features too.
func TestSystemImagesDeclareTheirFeatures(t *testing.T) {
	l, c, owner := agentLab(t)
	ctx := t.Context()
	plain := SystemImage{ID: "ubuntu@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("a", 64)}}
	corpus := SystemImage{ID: "ubuntu@2", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("c", 64)}, Features: []string{FeatureCorpusMount}}
	if err := l.s.ReportDeploymentHost(ctx, c.host, HostProvisioningBudget{MaxActive: 8, VCPUs: 16, UIDSlots: 10000, MemoryMiB: 16384}, []ImageDigests{plain.ImageDigests, corpus.ImageDigests}); err != nil {
		t.Fatal(err)
	}
	for _, image := range []SystemImage{plain, corpus} {
		r, err := c.ApproveSystemImage(ctx, l.platform, "approve-"+image.ID, image)
		var got SystemImage
		if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &got) != nil || got.Features == nil {
			t.Fatal("approval", image.ID, err, string(r.Body))
		}
	}
	shown := approvedImages(t, c, owner)
	if f := shown["ubuntu@1"].Features; f == nil || len(f) != 0 {
		t.Fatal("an image without features", f)
	}
	if f := shown["ubuntu@2"].Features; !slices.Equal(f, []string{FeatureCorpusMount}) {
		t.Fatal("an image's features", f)
	}
	for name, bad := range map[string][]string{"unknown": {"gpu"}, "twice": {FeatureCorpusMount, FeatureCorpusMount}, "empty": {""}} {
		image := SystemImage{ID: "ubuntu@3", ImageDigests: plain.ImageDigests, Features: bad}
		if _, err := c.ApproveSystemImage(ctx, l.platform, "bad-"+name, image); !errors.Is(err, ErrInput) {
			t.Error("approved features:", name, err)
		}
	}
	// The same approval again is accepted; other features are a conflict.
	if _, err := c.ApproveSystemImage(ctx, l.platform, "again", corpus); err != nil {
		t.Fatal("the same approval", err)
	}
	changed := plain
	changed.Features = []string{FeatureCorpusMount}
	if _, err := c.ApproveSystemImage(ctx, l.platform, "add-feature", changed); !errors.Is(err, ErrTransition) {
		t.Fatal("an approval gained a feature", err)
	}
	dropped := corpus
	dropped.Features = nil
	if _, err := c.ApproveSystemImage(ctx, l.platform, "drop-feature", dropped); !errors.Is(err, ErrTransition) {
		t.Fatal("an approval lost a feature", err)
	}
	if f := approvedImages(t, c, owner)["ubuntu@1"].Features; len(f) != 0 {
		t.Fatal("a refused approval changed an image", f)
	}
	// The database keeps the list closed.
	if _, err := l.s.pool.Exec(ctx, `UPDATE system_images SET features='{gpu}' WHERE id='ubuntu@1'`); err == nil {
		t.Fatal("the database accepted an unknown feature")
	}
}

// A release records the guest base its harness.yaml names; a release
// imported before, or approved locally, is of base 1.
func TestReleasesRecordTheirGuestBase(t *testing.T) {
	s, a, platform, _, _ := organizationLab(t)
	ctx := t.Context()
	imported := map[string]string{}
	for i, base := range []string{"", "agentcapsule-guest/1", "agentcapsule-guest/2"} {
		requestImport(t, a, platform, "k"+base, pinned(string(rune('a'+i))))
		release := rootfs(string(rune('a' + i)))
		release.Name, release.Base = "echo"+string(rune('a'+i)), base
		done, err := s.CompleteHarnessImport(ctx, claimImport(t, s), release)
		if err != nil || done.State != "READY" {
			t.Fatal("import of base", base, done, err)
		}
		imported[done.ReleaseID] = base
	}
	requestImport(t, a, platform, "k3", pinned("d"))
	bad := rootfs("d")
	bad.Base = "agentcapsule-guest/3"
	if _, err := s.CompleteHarnessImport(ctx, claimImport(t, s), bad); !errors.Is(err, ErrInput) {
		t.Fatal("an unknown base was recorded", err)
	}
	local, err := s.RegisterLocalRelease(ctx, HarnessReference{"builtin", "1.0.0"}, "sha256:"+strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	imported[local] = ""
	releases, err := a.ListHarnessReleases(ctx, platform, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range releases {
		want, ok := imported[r.ID]
		if !ok {
			continue
		}
		if want == "" {
			want = "agentcapsule-guest/1"
		}
		if r.Base != want {
			t.Fatal("base of", r.Name, r.Base, want)
		}
		delete(imported, r.ID)
	}
	if len(imported) != 0 {
		t.Fatal("releases not listed", imported)
	}
}

// Corpora are mounted only by a harness that has the mount point (a base-2
// release, or the system image's own built-in harness) on a system image
// whose capsule-init mounts them (corpus.mount). An agent created without a
// template records no system image, and cannot mount them (ADR 023 C7).
func TestCorporaNeedABaseTwoHarnessAndAMountingSystemImage(t *testing.T) {
	l, c, _ := agentLab(t)
	ctx := t.Context()
	builtIn := "sha256:" + strings.Repeat("a", 64) // the "reference" release of agentLab
	plain := SystemImage{ID: "plain@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("b", 64), builtIn}}
	mounting := SystemImage{ID: "mounting@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("c", 64), builtIn}, Features: []string{FeatureCorpusMount}}
	other := SystemImage{ID: "other@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("c", 64), "sha256:" + strings.Repeat("f", 64)}, Features: []string{FeatureCorpusMount}}
	if err := l.s.ReportDeploymentHost(ctx, c.host, HostProvisioningBudget{MaxActive: 8, VCPUs: 16, UIDSlots: 10000, MemoryMiB: 16384},
		[]ImageDigests{plain.ImageDigests, mounting.ImageDigests, other.ImageDigests}); err != nil {
		t.Fatal(err)
	}
	for _, image := range []SystemImage{plain, mounting, other} {
		if _, err := c.ApproveSystemImage(ctx, l.platform, "approve-"+image.ID, image); err != nil {
			t.Fatal(err)
		}
	}
	release := func(name, base string, i int) string {
		requestImport(t, l.a, l.platform, "import-"+name, pinned(string(rune('a'+i))))
		r := rootfs(string(rune('a' + i)))
		r.Name, r.Base = name, base
		done, err := l.s.CompleteHarnessImport(ctx, claimImport(t, l.s), r)
		if err != nil {
			t.Fatal(err)
		}
		return done.ReleaseID
	}
	base1, base2 := release("one", "agentcapsule-guest/1", 1), release("two", "agentcapsule-guest/2", 2)
	var reference string
	if err := l.s.pool.QueryRow(ctx, `SELECT id FROM harness_releases WHERE name='reference'`).Scan(&reference); err != nil {
		t.Fatal(err)
	}
	check := func(releaseID, image string) error {
		tx, err := l.s.begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollback(tx)
		return corporaMountable(ctx, tx, releaseID, image)
	}
	for _, ok := range []struct{ release, image string }{{base2, "mounting@1"}, {base2, "other@1"}, {reference, "mounting@1"}} {
		if err := check(ok.release, ok.image); err != nil {
			t.Error("refused", ok, err)
		}
	}
	for name, bad := range map[string]struct{ release, image string }{
		"base 1":                    {base1, "mounting@1"},
		"image without the feature": {base2, "plain@1"},
		"built-in without feature":  {reference, "plain@1"},
		"another image's built-in":  {reference, "other@1"},
		"no system image":           {base2, ""},
		"unknown image":             {base2, "none@1"},
		"unknown release":           {"rel_none", "mounting@1"},
	} {
		if err := check(bad.release, bad.image); !errors.Is(err, ErrCorpusIncompatible) {
			t.Error("accepted", name, err)
		}
	}
}
