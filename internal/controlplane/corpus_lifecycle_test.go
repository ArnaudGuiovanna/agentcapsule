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
