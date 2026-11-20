package controlplane

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCorpusFetchClaimsAndPublishesOnce(t *testing.T) {
	l, _, owner := agentLab(t)
	ctx := t.Context()
	input := CreateCorpusInput{Name: "school", Source: CorpusSource{Kind: "github", URL: "https://github.com/example/school", Ref: "main"}}
	r, err := l.a.CreateCorpus(ctx, owner, "declare", input)
	var c Corpus
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &c) != nil {
		t.Fatal("declare", r.Status, err)
	}
	if _, err = l.a.CreateCorpus(ctx, owner, "duplicate", input); !errors.Is(err, ErrCorpusNameTaken) {
		t.Fatal("duplicate", err)
	}
	builds := []CorpusBuild{}
	for _, key := range []string{"first", "second"} {
		r, err = l.a.RequestCorpusBuild(ctx, owner, c.ID, key, RequestCorpusBuildInput{})
		var b CorpusBuild
		if err != nil || r.Status != 202 || json.Unmarshal(r.Body, &b) != nil || b.State != "QUEUED" {
			t.Fatal("request", r.Status, err)
		}
		builds = append(builds, b)
	}
	claim := func() (CorpusWork, error) {
		return l.s.ClaimCorpusWork(ctx, "local", "worker", "builder@1", true, time.Hour)
	}
	j, err := claim()
	if err != nil || j.ID != builds[0].ID {
		t.Fatal("claim oldest", j, err)
	}
	if _, err = claim(); !errors.Is(err, ErrNoWork) {
		t.Fatal("second concurrent build", err)
	}
	sha := strings.Repeat("a", 40)
	if err = l.s.PinCorpusCommit(ctx, j, sha); err != nil {
		t.Fatal(err)
	}
	if err = l.s.PinCorpusCommit(ctx, j, strings.Repeat("b", 40)); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("mutable commit", err)
	}
	archive := map[string]any{"bytes": int64(4096), "sha256": strings.Repeat("a", 64)}
	if err = l.s.CompleteCorpusDownload(ctx, j, archive); err != nil {
		t.Fatal(err)
	}
	if err = l.s.FailCorpusWork(ctx, j, "unavailable", true, 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale lease", err)
	}
	if _, err = l.s.ClaimCorpusWork(ctx, "other", "worker", "builder@1", false, time.Hour); !errors.Is(err, ErrNoWork) {
		t.Fatal("changed host", err)
	}
	j, err = l.s.ClaimCorpusWork(ctx, "local", "worker", "builder@1", false, time.Hour)
	if err != nil || j.Phase != "SCANNING" || j.Commit != sha {
		t.Fatal("scanning", err, j)
	}
	if _, err = l.a.CancelCorpusBuild(ctx, owner, j.ID, "cancel"); err != nil {
		t.Fatal(err)
	}
	if err = l.s.FailCorpusWork(ctx, j, "unavailable", true, 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("canceled work", err)
	}
	j, err = claim()
	if err != nil || j.ID != builds[1].ID {
		t.Fatal("following build", err, j)
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	if _, err = l.s.pool.Exec(ctx, `UPDATE corpus_builds SET state='REVIEW',commit_sha=$2,image_digest=$3,image_bytes=8192,image_uuid='00000000-0000-4000-8000-000000000001',review_at=now(),review_expires_at=now()+interval '30 days',lease_token=NULL,lease_until=NULL WHERE id=$1`, j.ID, sha, digest); err != nil {
		t.Fatal(err)
	}
	r, err = l.a.PublishCorpusBuild(ctx, owner, j.ID, "publish", 1)
	var release CorpusRelease
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &release) != nil || release.Digest != digest {
		t.Fatal("publish", err, r.Status, release)
	}
	if _, err = l.a.PublishCorpusBuild(ctx, owner, j.ID, "again", 2); !errors.Is(err, ErrTransition) {
		t.Fatal("republish", err)
	}
	if _, err = l.a.DeprecateCorpusRelease(ctx, owner, release.ID, "deprecate"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.pool.Exec(ctx, "UPDATE corpus_releases SET digest=$2 WHERE id=$1", release.ID, "sha256:"+strings.Repeat("c", 64)); err == nil {
		t.Fatal("release modified")
	}
}

func TestCorpusBuilderIsPrivateAndClaimsItsOwnPhases(t *testing.T) {
	l, c, p := agentLab(t)
	ctx := t.Context()
	image := SystemImage{ID: "corpus@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("a", 64)}, Features: []string{FeatureCorpusMount}}
	if err := l.s.ReportDeploymentHost(ctx, "local", HostProvisioningBudget{MaxActive: 8, VCPUs: 16, MemoryMiB: 16384, UIDSlots: 1000}, []ImageDigests{image.ImageDigests}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApproveSystemImage(ctx, l.platform, "corpus-image", image); err != nil {
		t.Fatal(err)
	}
	var corpus Corpus
	r, err := l.a.CreateCorpus(ctx, p, "create", CreateCorpusInput{Name: "course", Source: CorpusSource{Kind: "github", URL: "https://github.com/school/course", Ref: "main"}})
	if err != nil || json.Unmarshal(r.Body, &corpus) != nil {
		t.Fatal(err)
	}
	if _, err = l.a.RequestCorpusBuild(ctx, p, corpus.ID, "request", RequestCorpusBuildInput{Commit: strings.Repeat("a", 40)}); err != nil {
		t.Fatal(err)
	}
	claim := func(fetch bool) CorpusWork {
		t.Helper()
		work, err := l.s.ClaimCorpusWork(ctx, "local", "worker", "reference@1.0.0", fetch, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return work
	}
	j := claim(true)
	if err = l.s.CompleteCorpusDownload(ctx, j, map[string]any{"bytes": 4096, "sha256": strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	j = claim(false)
	id, digest, ready, err := l.s.EnsureCorpusBuilder(ctx, j, HarnessReference{"reference", "1.0.0"}, AgentResources{1, 256, 64})
	if err != nil || ready || id == "" || digest != image.Initrd {
		t.Fatal("provision", err, digest, ready)
	}
	if _, err = c.GetTenantAgent(ctx, p, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("builder exposed", err)
	}
	if list, err := c.ListTenantAgents(ctx, p, "", 100); err != nil || len(list) != 0 {
		t.Fatal("builder listed", err, len(list))
	}
	if accounts, err := l.a.ListServiceAccounts(ctx, p, "", 100); err != nil || len(accounts) != 0 {
		t.Fatal("principal listed", err, len(accounts))
	}
	q, err := l.a.CurrentOrganizationQuotas(ctx, p)
	if err != nil || q.Usage.Agents != 0 || q.Usage.StorageMiB != 0 {
		t.Fatal("tenant quota", err, q.Usage)
	}
	if err = l.s.FinishCorpusScan(ctx, j, []any{}, map[string]int{"included": 1}, map[string]int{}, "", false); err != nil {
		t.Fatal(err)
	}
	j = claim(false)
	if j.Phase != "CONVERTING" {
		t.Fatal(j.Phase)
	}
	if err = l.s.FinishCorpusConversion(ctx, j, map[string]int{"converted": 1}); err != nil {
		t.Fatal(err)
	}
	j = claim(false)
	if j.Phase != "PACKAGING" {
		t.Fatal(j.Phase)
	}
	if _, err = l.a.CancelCorpusBuild(ctx, p, j.ID, "cancel"); err != nil {
		t.Fatal(err)
	}
}

// The pin observed by a boot belongs to this tenant and host. Deprecation
// stops new bindings, while a currently bound image remains collectible only
// after its last agent, review and active-release pin is gone.
func TestCorpusReviewPublicationAndBindingPins(t *testing.T) {
	l := newInvocationLab(t)
	ctx := t.Context()
	sha := strings.Repeat("a", 40)
	dig := "sha256:" + strings.Repeat("c", 64)
	image := SystemImage{ID: "mount@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("a", 64)}, Features: []string{FeatureCorpusMount}}
	if err := l.s.ReportDeploymentHost(ctx, "local", HostProvisioningBudget{MaxActive: 8, VCPUs: 16, MemoryMiB: 16384, UIDSlots: 1000}, []ImageDigests{image.ImageDigests}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.c.ApproveSystemImage(ctx, l.platform, "image", image); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(ctx, "UPDATE agent_specs SET system_image=$2 WHERE agent_id=$1", l.agent, image.ID); err != nil {
		t.Fatal(err)
	}
	r, err := l.a.CreateCorpus(ctx, l.owner, "declare", CreateCorpusInput{Name: "course", Source: CorpusSource{Kind: "github", URL: "https://github.com/school/course", Ref: "main"}})
	var c Corpus
	if err != nil || json.Unmarshal(r.Body, &c) != nil {
		t.Fatal(err)
	}
	review := func(key, digest string) string {
		t.Helper()
		r, err := l.a.RequestCorpusBuild(ctx, l.owner, c.ID, key, RequestCorpusBuildInput{Commit: sha})
		var b CorpusBuild
		if err != nil || json.Unmarshal(r.Body, &b) != nil {
			t.Fatal(err)
		}
		j := CorpusWork{ID: b.ID, Token: "token", Phase: "PACKAGING"}
		if _, err = l.s.pool.Exec(ctx, "UPDATE corpus_builds SET state='PACKAGING',host_id='local',builder='builder@1',lease_token='token',lease_until=now()+interval '1 hour' WHERE id=$1", b.ID); err != nil {
			t.Fatal(err)
		}
		if err = l.tr.CompleteCorpusReview(ctx, j, CorpusResult{Digest: digest, UUID: "11111111-1111-1111-1111-111111111111", Bytes: 8192, Files: map[string][]byte{"INDEX.md": []byte("Private contents"), "report.json": []byte("{}")}}); err != nil {
			t.Fatal(err)
		}
		return b.ID
	}
	b := review("a", dig)
	data, err := l.c.ReadCorpusReviewFile(ctx, l.owner, b, "INDEX.md")
	if err != nil || string(data) != "Private contents" {
		t.Fatal("read review", err)
	}
	if _, err = l.a.TryCorpusBuild(ctx, l.owner, b, "try", TryCorpusInput{AgentID: l.agent}); err != nil {
		t.Fatal(err)
	}
	discs, err := l.s.BootCorpora(ctx, l.agent, "local")
	if err != nil || len(discs) != 1 || discs[0].Digest != dig || discs[0].Mount != "course" {
		t.Fatal("try disk", discs, err)
	}
	if _, err = l.a.CancelCorpusBuild(ctx, l.owner, b, "cancel"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.c.ReadCorpusReviewFile(ctx, l.owner, b, "INDEX.md"); !errors.Is(err, ErrNotFound) {
		t.Fatal("read after purge", err)
	}
	if discs, err = l.s.BootCorpora(ctx, l.agent, "local"); err != nil || len(discs) != 0 {
		t.Fatal("canceled try", discs, err)
	}
	b = review("b", dig)
	r, err = l.a.PublishCorpusBuild(ctx, l.owner, b, "publish", 1)
	var rel CorpusRelease
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &rel) != nil {
		t.Fatal(err)
	}
	b = review("c", dig)
	r, err = l.a.PublishCorpusBuild(ctx, l.owner, b, "same", 1)
	if err != nil || r.Status != 200 {
		t.Fatal("same bytes", r.Status, err)
	}
	b = review("d", "sha256:"+strings.Repeat("b", 64))
	if _, err = l.a.PublishCorpusBuild(ctx, l.owner, b, "conflict", 1); !errors.Is(err, ErrCorpusVersionConflict) {
		t.Fatal("conflicting bytes", err)
	}
	if _, err = l.a.CancelCorpusBuild(ctx, l.owner, b, "cancel-conflict"); err != nil {
		t.Fatal(err)
	}
	in := []CorpusBinding{{Name: "course", Version: 1}}
	if _, err = l.a.SetAgentCorpora(ctx, l.owner, l.agent, "bind", in); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.DeprecateCorpusRelease(ctx, l.owner, rel.ID, "deprecate"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.SetAgentCorpora(ctx, l.owner, l.agent, "bind-again", in); !errors.Is(err, ErrCorpusUnavailable) {
		t.Fatal("rebind deprecated", err)
	}
	pins, err := l.s.CorpusImagesInUse(ctx, "local")
	if err != nil || len(pins) != 1 || pins[0] != dig {
		t.Fatal("binding no longer pins", pins, err)
	}
	if _, err = l.a.SetAgentCorpora(ctx, l.owner, l.agent, "unbind", []CorpusBinding{}); err != nil {
		t.Fatal(err)
	}
	if pins, err = l.s.CorpusImagesInUse(ctx, "local"); err != nil || len(pins) != 0 {
		t.Fatal("unbound pin", pins, err)
	}
}
