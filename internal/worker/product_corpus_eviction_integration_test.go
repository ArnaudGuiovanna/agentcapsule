//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg/source"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// A separate local fixture has two revisions. The original private repository
// and its credential are independent of the cache-retention test.
func cacheCourseArchive(t *testing.T, revision int) []byte {
	t.Helper()
	manifest, err := source.Template("Cache course", "en")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tarball := tar.NewWriter(gz)
	for _, file := range []struct {
		name string
		data []byte
	}{{"agentcapsule-corpus.yaml", manifest}, {"lesson.md", []byte(fmt.Sprintf("# Revision %d\nCourse revision %d.\n", revision, revision))}} {
		if err = tarball.WriteHeader(&tar.Header{Name: "forge-cache/" + file.name, Size: int64(len(file.data)), Mode: 0644}); err != nil {
			t.Fatal(err)
		}
		if _, err = tarball.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err = tarball.Close(); err != nil {
		t.Fatal(err)
	}
	if err = gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func verifyCorpusEviction(t *testing.T, l *productPeerLab, g corpusGuest, owner func() string, spec controlplane.TemplateSpec, deployment string, agents []string) {
	t.Helper()
	const repo = "fixture/cache-course"
	payload := map[string][]byte{}
	for _, v := range []int{3, 4} {
		sha := strings.Repeat(strconv.Itoa(v), 40)
		payload["/repos/"+repo+"/tarball/"+sha] = cacheCourseArchive(t, v)
	}
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := payload[r.URL.Path]
		if r.Header.Get("Authorization") != "" || b == nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	defer local.Close()
	host := strings.TrimPrefix(local.URL, "http://")
	fetcher, err := corpussource.New(corpussource.Policy{Rules: []corpussource.Rule{{Kind: corpussource.GitHub, Host: "github.com", APIHost: host, Repositories: []string{repo}, Local: true}}, AllowedInternalHosts: []string{host}}, g.source.Limits)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewCorpusFetcher(corpusFetchStore{l.store, "local", g.harness.Name + "@" + g.harness.Version}, fetcher, l.accounts, g.source.Staging, "cache-source")
	if err != nil {
		t.Fatal(err)
	}
	var course controlplane.Corpus
	l.request(owner(), "POST", "/v1/corpora", "cache-course", controlplane.CreateCorpusInput{Name: "cache-course", Source: controlplane.CorpusSource{Kind: "github", URL: "https://github.com/" + repo, Ref: "main"}}, 201, &course)
	ctx := t.Context()
	build := func(v int) controlplane.CorpusRelease {
		t.Helper()
		key := "cache-build-" + strconv.Itoa(v)
		var b controlplane.CorpusBuild
		l.request(owner(), "POST", "/v1/corpora/"+course.ID+"/builds", key, controlplane.RequestCorpusBuildInput{Commit: strings.Repeat(strconv.Itoa(v), 40)}, 202, &b)
		if ok, err := d.FetchOne(ctx); err != nil || !ok {
			t.Fatal("cache source", v, err)
		}
		l.awaitFor(key, true, 5*time.Minute, func() bool {
			if _, err := g.one(ctx); err != nil {
				t.Fatal(err)
			}
			l.request(owner(), "GET", "/v1/corpus-builds/"+b.ID, "", nil, 200, &b)
			if b.State == "FAILED" {
				t.Fatal("cache build", v, b.ErrorCode)
			}
			return b.State == "REVIEW"
		})
		var release controlplane.CorpusRelease
		l.request(owner(), "POST", "/v1/corpus-builds/"+b.ID+"/publish", key, map[string]int{"version": v}, 201, &release)
		return release
	}
	old, next := build(3), build(4)
	if old.Digest == next.Digest {
		t.Fatal("revisions have the same image")
	}
	roll := func(r controlplane.CorpusRelease) {
		t.Helper()
		key := "cache-rollout-" + strconv.Itoa(r.Version)
		spec.Corpora = []controlplane.CorpusBinding{{Name: r.Name, Version: r.Version, Mount: "lessons"}}
		var target controlplane.TemplateRevision
		l.request(owner(), "POST", "/v1/templates", key, spec, 201, &target)
		var rollout controlplane.Rollout
		l.request(owner(), "POST", "/v1/deployments/"+deployment+"/rollouts", key, controlplane.RolloutInput{Template: target.Reference, MaxUnavailable: 1}, 202, &rollout)
		l.awaitFor(key, true, 5*time.Minute, func() bool {
			l.request(owner(), "GET", "/v1/rollouts/"+rollout.ID, "", nil, 200, &rollout)
			if rollout.Status == "paused" {
				t.Fatal("cache rollout paused", rollout.Reason)
			}
			return rollout.Status == "completed"
		})
		if rollout.Updated != len(agents) {
			t.Fatal("cache rollout members", rollout.Updated)
		}
		// The deployment has a zero warm target. Explicitly boot readers after
		// each rollout to check the physical mounts even when it left them idle.
		for _, id := range agents {
			var op controlplane.AgentCreation
			l.request(owner(), "POST", "/v1/agents/"+id+"/wake", key+"-"+id, struct{}{}, 202, &op)
			l.awaitOperation(owner, op.OperationID)
		}
	}
	roll(old)
	l.request(owner(), "POST", "/v1/corpus-releases/"+old.ID+"/deprecate", "retire-cache-v3", struct{}{}, 200, nil)
	gc := GarbageCollection{Store: l.store, HostID: "local", RuntimeRoot: l.root, CorpusCache: g.source.Cache}
	path := func(digest string) string {
		return filepath.Join(l.worker.corpusCache.dir(digest), corpuspkg.ImageFile)
	}
	inode, err := os.Stat(path(old.Digest))
	if err != nil {
		t.Fatal(err)
	}
	runs := l.runs(len(agents))
	for _, id := range agents {
		held, err := os.Stat(filepath.Join(l.root, "jails", "firecracker", runs[id].ID, "root", "corpus0.ext4"))
		if err != nil || !os.SameFile(inode, held) {
			t.Fatal("deprecated v3 mount", err)
		}
	}
	checkPins := func(databasePin, runningPin bool) {
		t.Helper()
		durable, err := l.store.CorpusImagesInUse(ctx, "local")
		if err != nil {
			t.Fatal(err)
		}
		physical, err := runtime.CorpusImagesInUseAt(ctx, l.root)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(durable, old.Digest) != databasePin || physical[old.Digest] != runningPin {
			t.Fatal("durable or running v3 pin", databasePin, runningPin)
		}
	}
	checkPins(true, true)
	// Binding changes apply on next boot. Remove all durable v3 references
	// while the three running VMMs still hold the exact old inode.
	for _, id := range agents {
		var changed controlplane.AgentCorpora
		l.request(owner(), "POST", "/v1/agents/"+id+"/corpora", "next-"+id, map[string]any{"corpora": []controlplane.CorpusBinding{{Name: next.Name, Version: next.Version, Mount: "lessons"}}}, 200, &changed)
		if len(changed.Corpora) != 1 || changed.Corpora[0].Digest != next.Digest {
			t.Fatal("pending v4 binding")
		}
	}
	checkPins(false, true)
	kept, err := gc.Run(ctx, false)
	if err != nil || kept.Corpora == nil || slices.Contains(kept.Corpora.Unused, old.Digest) {
		t.Fatal("collection while v3 is mounted", err)
	}
	retained, err := os.Stat(path(old.Digest))
	if err != nil || !os.SameFile(inode, retained) {
		t.Fatal("deprecated but mounted cache image lost", err)
	}
	roll(next)
	checkPins(false, false)
	reclaimed, err := gc.Run(ctx, false)
	if err != nil || reclaimed.Corpora == nil || !slices.Contains(reclaimed.Corpora.Unused, old.Digest) || slices.Contains(reclaimed.Corpora.Unused, next.Digest) {
		t.Fatal("collection after rollout", err)
	}
	if _, err = os.Stat(path(old.Digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired cache image remains", err)
	}
	if _, err = os.Stat(path(next.Digest)); err != nil {
		t.Fatal("current cache image lost", err)
	}
	t.Logf("COR-009: deprecated v3 %s retained across collection solely by %d running guests after database unpinning, then evicted after rollout to v4 %s", old.Digest, len(agents), next.Digest)
}
