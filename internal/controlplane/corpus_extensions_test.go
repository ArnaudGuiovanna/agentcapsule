package controlplane

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestCorpusExtensionsPinTheReviewedBaseAndPublishedSnapshot(t *testing.T) {
	l := newInvocationLab(t)
	ctx := t.Context()
	sql := func(q string, args ...any) {
		t.Helper()
		if _, err := l.s.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	system := SystemImage{ID: "enrichment@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("a", 64)}, Features: []string{FeatureCorpusMount, FeatureCorpusExtensions}}
	if err := l.s.ReportDeploymentHost(ctx, "local", HostProvisioningBudget{MaxActive: 8, VCPUs: 16, MemoryMiB: 16384, UIDSlots: 1000}, []ImageDigests{system.ImageDigests}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.c.ApproveSystemImage(ctx, l.platform, "system", system); err != nil {
		t.Fatal(err)
	}
	sql("UPDATE agent_specs SET system_image=$2 WHERE agent_id=$1", l.agent, system.ID)
	sql(`INSERT INTO harness_releases(id,name,version,artifact_digest,source,reference,rootfs_digest,rootfs_bytes,base) VALUES('hrn-test','enricher','1','sha256:'||repeat('d',64),'oci','registry.example/demo','sha256:'||repeat('e',64),4096,'agentcapsule-guest/2')`)
	auth := AuthorizeCorpusEnricherInput{Name: "links", Harness: HarnessReference{"enricher", "1"}}
	if _, err := l.a.AuthorizeCorpusEnricher(ctx, l.owner, "unsigned", auth); !errors.Is(err, ErrRelease) {
		t.Fatal("unsigned", err)
	}
	sql("UPDATE harness_releases SET signer='sha256:'||repeat('c',64) WHERE id='hrn-test'")
	r, err := l.a.AuthorizeCorpusEnricher(ctx, l.owner, "signed", auth)
	var enr CorpusEnricher
	if err != nil || json.Unmarshal(r.Body, &enr) != nil {
		t.Fatal("authorize", err)
	}
	var c Corpus
	r, err = l.a.CreateCorpus(ctx, l.owner, "declare", CreateCorpusInput{Name: "school", Source: CorpusSource{Kind: "github", URL: "https://github.com/example/school", Ref: "main"}})
	if err != nil || json.Unmarshal(r.Body, &c) != nil {
		t.Fatal("declare", err)
	}
	baseDigest := "sha256:" + strings.Repeat("1", 64)
	makeReview := func(key string) string {
		t.Helper()
		id := newID("cbd")
		sql(`INSERT INTO corpus_builds(id,tenant_id,corpus_id,state,requested_ref,commit_sha,host_id,builder,image_digest,image_uuid,image_bytes,review_at,review_expires_at) VALUES($1,$2,$3,'REVIEW',$4,repeat('a',40),'local','builder@1',$5,'11111111-1111-1111-1111-111111111111',8192,clock_timestamp(),clock_timestamp()+interval '1 day')`, id, l.owner.TenantID, c.ID, key, baseDigest)
		return id
	}
	b := makeReview("first")
	var x CorpusExtension
	r, err = l.a.RequestCorpusExtension(ctx, l.owner, b, "enrich", RequestCorpusExtensionInput{enr.ID})
	if err != nil || json.Unmarshal(r.Body, &x) != nil || x.State != "QUEUED" {
		t.Fatal("request", x, err)
	}
	if _, err = l.a.PublishCorpusBuild(ctx, l.owner, b, "too-early", 1); !errors.Is(err, ErrTransition) {
		t.Fatal("unfinished extension", err)
	}
	w, err := l.s.ClaimCorpusExtension(ctx, "local")
	if err != nil || w.ID != x.ID {
		t.Fatal("claim", w, err)
	}
	if _, err = l.s.ClaimCorpusExtension(ctx, "local"); !errors.Is(err, ErrNoWork) {
		t.Fatal("concurrent claim", err)
	}
	private, ready, err := l.s.EnsureCorpusEnricher(ctx, w, AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 64})
	if err != nil || ready || private == "" {
		t.Fatal("provision", private, ready, err)
	}
	mounts, err := l.s.BootCorpora(ctx, private, "local")
	if err != nil || len(mounts) != 1 || mounts[0].Mount != "base" || mounts[0].Digest != baseDigest {
		t.Fatal("private guest disks", mounts, err)
	}
	wanted := CorpusExtensionImage{Name: "links", UUID: "22222222-2222-2222-2222-222222222222", Digest: "sha256:" + strings.Repeat("2", 64), Bytes: 4096}
	if err = l.s.SettleCorpusExtension(ctx, w, &wanted, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.TryCorpusBuild(ctx, l.owner, b, "try", TryCorpusInput{AgentID: l.agent}); err != nil {
		t.Fatal(err)
	}
	disks, err := l.s.BootCorpora(ctx, l.agent, "local")
	if err != nil || len(disks) != 2 || disks[1].Parent != "school" || disks[1].Mount != "links" || disks[1].Digest != wanted.Digest {
		t.Fatal("trial", disks, err)
	}
	r, err = l.a.PublishCorpusBuild(ctx, l.owner, b, "publish", 1)
	var release CorpusRelease
	if err != nil || json.Unmarshal(r.Body, &release) != nil || !slices.Equal(release.Extensions, []CorpusExtensionImage{wanted}) {
		t.Fatal("publish", release, err)
	}
	if _, err = l.a.SetAgentCorpora(ctx, l.owner, l.agent, "bind", []CorpusBinding{{Name: "school", Version: 1, Mount: "lesson"}}); err != nil {
		t.Fatal(err)
	}
	disks, err = l.s.BootCorpora(ctx, l.agent, "local")
	if err != nil || len(disks) != 2 || disks[1].Parent != "lesson" {
		t.Fatal("published boot", disks, err)
	}
	if _, err = l.a.PublishCorpusBuild(ctx, l.owner, makeReview("different"), "snapshot-conflict", 1); !errors.Is(err, ErrCorpusVersionConflict) {
		t.Fatal("snapshot conflict", err)
	}
	if _, err = l.a.DeprecateCorpusRelease(ctx, l.owner, release.ID, "deprecate"); err != nil {
		t.Fatal(err)
	}
	pins, err := l.s.CorpusImagesInUse(ctx, "local")
	if err != nil || !slices.Contains(pins, wanted.Digest) {
		t.Fatal("bound extension evicted", pins, err)
	}
	if _, err = l.a.SetAgentCorpora(ctx, l.owner, l.agent, "unbind", []CorpusBinding{}); err != nil {
		t.Fatal(err)
	}
	pins, err = l.s.CorpusImagesInUse(ctx, "local")
	if err != nil || slices.Contains(pins, wanted.Digest) {
		t.Fatal("unbound extension pinned", pins, err)
	}
	b = makeReview("cancel")
	if _, err = l.a.RequestCorpusExtension(ctx, l.owner, b, "enrich-again", RequestCorpusExtensionInput{enr.ID}); err != nil {
		t.Fatal(err)
	}
	w, err = l.s.ClaimCorpusExtension(ctx, "local")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.CancelCorpusBuild(ctx, l.owner, b, "cancel"); err != nil {
		t.Fatal(err)
	}
	if err = l.s.SettleCorpusExtension(ctx, w, &wanted, ""); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale lease", err)
	}
}
