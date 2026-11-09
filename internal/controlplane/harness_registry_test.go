package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func pinned(c string) string { return "ghcr.io/acme/echo@sha256:" + strings.Repeat(c, 64) }

func requestImport(t *testing.T, a *Accounts, p Principal, key, ref string) (HarnessImport, APIReceipt) {
	t.Helper()
	r, err := a.RequestHarnessImport(t.Context(), p, key, HarnessImportInput{Reference: ref})
	if err != nil {
		t.Fatal("request import", err)
	}
	var v HarnessImport
	if err = json.Unmarshal(r.Body, &v); err != nil {
		t.Fatal(err)
	}
	return v, r
}

func claimImport(t *testing.T, s *Store) ImportJob {
	t.Helper()
	job, err := s.ClaimHarnessImport(t.Context(), "worker-a", time.Minute)
	if err != nil {
		t.Fatal("claim", err)
	}
	return job
}

func rootfs(c string) ImportedRelease {
	return ImportedRelease{Name: "echo", Version: "1.0.0", RootfsDigest: "sha256:" + strings.Repeat(c, 64), RootfsBytes: 4 << 20}
}

func TestHarnessImportBecomesAnImmutableRelease(t *testing.T) {
	s, a, platform, _, legacy := organizationLab(t)
	if _, err := a.RequestHarnessImport(t.Context(), platform, "bad", HarnessImportInput{Reference: "ghcr.io/acme/echo:latest"}); !errors.Is(err, ErrInput) {
		t.Fatal("an unpinned reference was accepted", err)
	}
	if _, err := a.RequestHarnessImport(t.Context(), legacy, "x", HarnessImportInput{Reference: pinned("a")}); !errors.Is(err, ErrForbidden) {
		t.Fatal("a non-platform principal requested an import", err)
	}
	first, r := requestImport(t, a, platform, "k1", pinned("a"))
	if r.Status != 202 || first.State != "IMPORTING" || first.Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatal("import", r.Status, first)
	}
	if again, r := requestImport(t, a, platform, "k1", pinned("a")); !r.Replayed || again.ID != first.ID {
		t.Fatal("replay", r.Replayed)
	}
	// The same package requested again under another key joins the import in flight.
	if dup, _ := requestImport(t, a, platform, "k2", pinned("a")); dup.ID != first.ID {
		t.Fatal("a second import of the same package started", dup.ID)
	}
	job := claimImport(t, s)
	if job.ID != first.ID || job.Digest != first.Digest || job.Attempt != 1 {
		t.Fatal("claimed job", job)
	}
	if _, err := s.ClaimHarnessImport(t.Context(), "worker-b", time.Minute); !errors.Is(err, ErrNoWork) {
		t.Fatal("a leased import was claimed twice", err)
	}
	done, err := s.CompleteHarnessImport(t.Context(), job, rootfs("1"))
	if err != nil || done.State != "READY" || done.ReleaseID == "" {
		t.Fatal("complete", done, err)
	}
	if got, err := a.GetHarnessImport(t.Context(), platform, first.ID); err != nil || got.State != "READY" {
		t.Fatal("import view", got, err)
	}
	items, err := a.ListHarnessReleases(t.Context(), platform, false)
	if err != nil || len(items) != 1 || items[0].State != "READY" || items[0].Source != "oci" || items[0].Digest != first.Digest ||
		items[0].RootfsBytes != 4<<20 || items[0].Reference != pinned("a") {
		t.Fatal("release list", items, err)
	}
	// An already released package is answered at once; nothing is downloaded again.
	if again, r := requestImport(t, a, platform, "k3", pinned("a")); r.Status != 200 || again.State != "READY" {
		t.Fatal("released package re-imported", r.Status, again)
	}
	if _, err = s.ClaimHarnessImport(t.Context(), "worker-a", time.Minute); !errors.Is(err, ErrNoWork) {
		t.Fatal("work left after a released package", err)
	}
	// name:version is immutable: another package claiming it is rejected.
	requestImport(t, a, platform, "k4", pinned("b"))
	conflict, err := s.CompleteHarnessImport(t.Context(), claimImport(t, s), rootfs("2"))
	if err != nil || conflict.State != "REJECTED" || conflict.ErrorCode != "version_conflict" {
		t.Fatal("version rebinding accepted", conflict, err)
	}
	if items, _ = a.ListHarnessReleases(t.Context(), platform, false); len(items) != 1 || items[0].Digest != first.Digest {
		t.Fatal("the release changed digest", items)
	}
}

func TestHarnessImportRetriesTransientFailuresThenRejects(t *testing.T) {
	s, a, platform, _, _ := organizationLab(t)
	imp, _ := requestImport(t, a, platform, "k", pinned("c"))
	for attempt := 1; attempt <= MaxImportAttempts; attempt++ {
		job := claimImport(t, s)
		if job.Attempt != attempt {
			t.Fatal("attempt", job.Attempt, attempt)
		}
		v, err := s.FailHarnessImport(t.Context(), job, "unavailable", true, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if attempt < MaxImportAttempts {
			if v.State != "IMPORTING" {
				t.Fatal("a transient failure ended the import", v)
			}
			if _, err = s.ClaimHarnessImport(t.Context(), "worker-a", time.Minute); !errors.Is(err, ErrNoWork) {
				t.Fatal("retried before its backoff", err)
			}
			if _, err = s.pool.Exec(t.Context(), "UPDATE harness_imports SET next_attempt_at=clock_timestamp() WHERE id=$1", imp.ID); err != nil {
				t.Fatal(err)
			}
		} else if v.State != "REJECTED" || v.ErrorCode != "unavailable" {
			t.Fatal("the last attempt did not reject", v)
		}
	}
	// A permanent cause rejects at once; a lost lease cannot complete anything.
	requestImport(t, a, platform, "p", pinned("d"))
	if v, err := s.FailHarnessImport(t.Context(), claimImport(t, s), "policy", false, 0); err != nil || v.ErrorCode != "policy" {
		t.Fatal("policy rejection", v, err)
	}
	requestImport(t, a, platform, "l", pinned("e"))
	job := claimImport(t, s)
	if _, err := s.pool.Exec(t.Context(), "UPDATE harness_imports SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteHarnessImport(t.Context(), job, rootfs("3")); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("an expired lease completed an import", err)
	}
	// A rejected package can be requested again.
	if again, r := requestImport(t, a, platform, "p2", pinned("d")); r.Status != 202 || again.State != "IMPORTING" {
		t.Fatal("retry after rejection", r.Status, again)
	}
}

func TestConcurrentImportsOfOneVersionYieldOneRelease(t *testing.T) {
	s, a, platform, _, _ := organizationLab(t)
	var jobs []ImportJob
	for i, c := range []string{"1", "2", "3", "4"} {
		requestImport(t, a, platform, fmt.Sprintf("k%d", i), pinned(c))
		jobs = append(jobs, claimImport(t, s))
	}
	var wg sync.WaitGroup
	results := make(chan HarnessImport, len(jobs))
	for i, job := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.CompleteHarnessImport(t.Context(), job, rootfs(fmt.Sprint(i+5)))
			if err != nil {
				t.Error(err)
			}
			results <- v
		}()
	}
	wg.Wait()
	close(results)
	ready := 0
	for v := range results {
		switch {
		case v.State == "READY":
			ready++
		case v.State != "REJECTED" || v.ErrorCode != "version_conflict":
			t.Fatal(v)
		}
	}
	if ready != 1 {
		t.Fatal("releases for one version", ready)
	}
}

func TestReleasesAreListedToMembersAndDeprecatedByThePlatform(t *testing.T) {
	l, c, owner := agentLab(t)
	platform := l.platform
	requestImport(t, l.a, platform, "k", pinned("f"))
	done, err := l.s.CompleteHarnessImport(t.Context(), claimImport(t, l.s), ImportedRelease{Name: "imported", Version: "1.0.0", RootfsDigest: "sha256:" + strings.Repeat("9", 64), RootfsBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	items, err := l.a.ListHarnessReleases(t.Context(), owner, false)
	if err != nil || !slicesContainRelease(items, done.ReleaseID) {
		t.Fatal("a member cannot see the releases", err)
	}
	// An imported release backs agents like a local one; the worker boots its image.
	in := tenantAgentInput("on-oci")
	in.Harness = HarnessReference{Name: "imported", Version: "1.0.0"}
	if _, err = c.Reserve(t.Context(), owner, "oci", in); err != nil {
		t.Fatal("an agent could not use an imported release", err)
	}
	var source, rootfs string
	if err = l.s.pool.QueryRow(t.Context(), `SELECT r.source,r.rootfs_digest FROM agent_specs x JOIN harness_releases r ON r.id=x.release_id
        WHERE x.name='on-oci'`).Scan(&source, &rootfs); err != nil || source != "oci" || rootfs != "sha256:"+strings.Repeat("9", 64) {
		t.Fatal("agent not pinned to the imported release", source, rootfs, err)
	}
	if _, err = l.a.DeprecateHarnessRelease(t.Context(), owner, done.ReleaseID, "x"); !errors.Is(err, ErrForbidden) {
		t.Fatal("a member deprecated a release", err)
	}
	r, err := l.a.DeprecateHarnessRelease(t.Context(), platform, done.ReleaseID, "dep")
	var v HarnessRelease
	if err != nil || json.Unmarshal(r.Body, &v) != nil || v.State != "DEPRECATED" || v.DeprecatedAt == nil {
		t.Fatal("deprecate", err, v)
	}
	if items, _ = l.a.ListHarnessReleases(t.Context(), owner, false); slicesContainRelease(items, done.ReleaseID) {
		t.Fatal("a deprecated release is still offered")
	}
	if items, _ = l.a.ListHarnessReleases(t.Context(), owner, true); !slicesContainRelease(items, done.ReleaseID) {
		t.Fatal("a deprecated release vanished from the full list")
	}
	var audits int
	if err = l.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM harness_audit").Scan(&audits); err != nil || audits != 2 {
		t.Fatal("audit", audits, err)
	}
}

func slicesContainRelease(items []HarnessRelease, id string) bool {
	for _, v := range items {
		if v.ID == id {
			return true
		}
	}
	return false
}
