//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/registrytest"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

type gitHubCorpusFixture struct {
	Archive    string `json:"archive"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	Commit     string `json:"commit"`
	Repository string `json:"repository"`
	PDF        string `json:"pdf"`
}

// Serve package files directly from disk. The ordinary worker imports its OCI
// manifest by digest, verifies each layer, and inspects the rootfs.
func corpusBuilderRegistry(t *testing.T, pkg string) (ociregistry.Rule, string) {
	t.Helper()
	type descriptor struct {
		Type   string `json:"mediaType"`
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	}
	const media = "application/vnd.oci.image.manifest.v1+json"
	paths := map[string]string{}
	layers := []descriptor{}
	for _, layer := range []struct{ name, typ string }{{harnesspkg.ManifestFile, harnesspkg.ManifestMediaType}, {harnesspkg.ChecksumsFile, harnesspkg.ChecksumsMediaType}, {harnesspkg.RootfsFile, harnesspkg.RootfsMediaType}} {
		p := filepath.Join(pkg, layer.name)
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
		paths[digest] = p
		layers = append(layers, descriptor{layer.typ, digest, n})
	}
	raw, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": media, "artifactType": harnesspkg.ArtifactType, "config": descriptor{"application/vnd.oci.empty.v1+json", harnesspkg.Digest([]byte("{}")), 2}, "layers": layers})
	if err != nil {
		t.Fatal(err)
	}
	const repo = "courses/builder"
	backing := registrytest.New()
	t.Cleanup(backing.Close)
	digest := backing.PutManifest(repo, raw)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d, ok := strings.CutPrefix(r.URL.Path, "/v2/"+repo+"/blobs/"); ok && paths[d] != "" {
			http.ServeFile(w, r, paths[d])
			return
		}
		backing.Server.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(registry.Close)
	rule := ociregistry.Rule{Host: strings.TrimPrefix(registry.URL, "http://"), Repositories: []string{repo}, Local: true}
	return signCorpusTestRelease(t, rule, ociregistry.Reference{Registry: rule.Host, Repository: repo, Digest: digest})
}

func courseEnricherRegistry(t *testing.T, pkg string) (ociregistry.Rule, string) {
	t.Helper()
	reg := registrytest.New()
	t.Cleanup(reg.Close)
	rule := ociregistry.Rule{Host: reg.Host(), Repositories: []string{"courses/enricher"}, Local: true}
	ref, err := ociregistry.Push(t.Context(), rule, "courses/enricher", "1.0.0", pkg)
	if err != nil {
		t.Fatal(err)
	}
	return signCorpusTestRelease(t, rule, ref)
}

func signCorpusTestRelease(t *testing.T, rule ociregistry.Rule, ref ociregistry.Reference) (ociregistry.Rule, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ociregistry.Sign(t.Context(), rule, ref, key); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := ociregistry.ParsePublisherKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	rule.Keys = []ociregistry.PublisherKey{trusted}
	return rule, ref.String()
}

func gitHubCorpusSource(t *testing.T, fixture gitHubCorpusFixture, tokenPath string) (corpussource.Policy, string) {
	t.Helper()
	rule := corpussource.Rule{Kind: corpussource.GitHub, Host: "github.com", Repositories: []string{fixture.Repository}}
	if tokenPath != "" {
		raw, err := operatorconfig.ReadPrivateUpTo(tokenPath, 4096)
		if err != nil {
			t.Fatal("cannot read private GitHub credential file")
		}
		defer clear(raw)
		rule.ArchiveHosts = []string{"codeload.github.com"}
		t.Log("source mode: live private GitHub, authenticated API and archive hosts", rule.Host, "api.github.com", rule.ArchiveHosts[0])
		return corpussource.Policy{Rules: []corpussource.Rule{rule}}, string(bytes.TrimSpace(raw))
	}
	file, err := os.Open(fixture.Archive)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	n, err := io.CopyN(h, file, fixture.Bytes)
	file.Close()
	if err != nil || n != fixture.Bytes || hex.EncodeToString(h.Sum(nil)) != fixture.SHA256 {
		t.Fatal("GitHub archive checksum", err)
	}
	// The scoped replay credential is unrelated to the token used for capture.
	const token = "fixture-read-only-token"
	forge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "scope", 403)
			return
		}
		if r.URL.Path != "/repos/"+fixture.Repository+"/tarball/"+fixture.Commit {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(fixture.Archive)
		if err != nil {
			http.Error(w, "fixture", 500)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/gzip")
		io.CopyN(w, f, fixture.Bytes)
	}))
	t.Cleanup(forge.Close)
	rule.APIHost = strings.TrimPrefix(forge.URL, "http://")
	rule.Local = true
	t.Log("source mode: authenticated local replay of captured GitHub archive")
	return corpussource.Policy{Rules: []corpussource.Rule{rule}, AllowedInternalHosts: []string{rule.APIHost}}, token
}

// The fixture contains the bytes and SHA-256 captured from a private GitHub
// repository. A private token file selects live GitHub; otherwise the test replays the capture locally.
func TestCorpusBuilderAndConsumerOnKVM(t *testing.T) {
	pkg := os.Getenv("AGENTCAPSULE_KVM_CORPUS_BUILDER")
	source := os.Getenv("AGENTCAPSULE_KVM_GITHUB_CORPUS")
	var fixture gitHubCorpusFixture
	b, err := os.ReadFile(source)
	if err != nil || json.Unmarshal(b, &fixture) != nil || fixture.Bytes < 1 || !corpusmeta.ValidCommit(fixture.Commit) {
		t.Fatal("missing or invalid GitHub corpus fixture")
	}
	rule, ref := corpusBuilderRegistry(t, pkg)
	tokenPath := os.Getenv("AGENTCAPSULE_KVM_GITHUB_CORPUS_TOKEN_FILE")
	policy, token := gitHubCorpusSource(t, fixture, tokenPath)
	labRuntimeOptions = func(o *runtime.FirecrackerOptions) { o.MaxActive = 4 }
	defer func() { labRuntimeOptions = nil }()
	lab := newProductPeerLab(t)
	ctx := t.Context()
	identity, org, platform := lab.installTenant(t)
	owner := func() string { return identity.tokenFor(t, "alice", tenantKVMScopes+" corpus:manage corpus:read") }
	cli := configureCorpusWatch(t, lab, org.ID, owner())
	reviewer := corpusReviewAdmin(t, lab, identity, owner())
	if err = lab.store.ConfigureHostStorage(ctx, "local", 8192); err != nil {
		t.Fatal(err)
	}
	rules := []ociregistry.Rule{rule}
	var signed, signer string
	if pkg := os.Getenv("AGENTCAPSULE_KVM_COURSE_ENRICHER"); pkg != "" {
		enricher, reference := courseEnricherRegistry(t, pkg)
		signed, signer = reference, enricher.Keys[0].ID
		rules = append(rules, enricher)
	}
	fetcher, err := ociregistry.NewFetcher(ociregistry.Policy{Rules: rules, RequireSignatures: true}, 3<<30)
	if err != nil {
		t.Fatal(err)
	}
	inspect := sandbox.Options{UID: labInspectionUID, GID: labInspectionUID}
	fetcher.Sandbox = inspect
	importer, err := NewHarnessImporter(lab.store, fetcher, filepath.Join(lab.root, "releases"), "builder-importer")
	if err != nil {
		t.Fatal(err)
	}
	if err = lab.worker.EnableRegistry(importer); err != nil {
		t.Fatal(err)
	}
	importPackage := func(key, reference, expectedSigner string) {
		t.Helper()
		var imp controlplane.HarnessImport
		lab.request(platform, "POST", "/v1/harness-imports", key, controlplane.HarnessImportInput{Reference: reference}, 202, &imp)
		if work, err := importer.ImportOne(ctx); err != nil || !work {
			t.Fatal("import", work, err)
		}
		lab.request(platform, "GET", "/v1/harness-imports/"+imp.ID, "", nil, 200, &imp)
		if imp.State != "READY" {
			t.Fatal("harness import", key, imp.State, imp.ErrorCode)
		}
		var publisher string
		if err := lab.db.QueryRow(ctx, "SELECT signer FROM harness_releases WHERE id=$1", imp.ReleaseID).Scan(&publisher); err != nil || publisher != expectedSigner {
			t.Fatal("imported harness publisher", key, err)
		}
		t.Log("imported signed OCI release", key, imp.Digest, publisher)

	}
	importPackage("import", ref, rule.Keys[0].ID)
	if signed != "" {
		importPackage("import-enricher", signed, signer)
	}
	image := controlplane.SystemImage{ID: "corpus@1", ImageDigests: controlplane.ImageDigests{Kernel: "sha256:" + digest(t, config(t).Kernel), Initrd: "sha256:" + digest(t, config(t).Initrd)}, Features: []string{controlplane.FeatureCorpusMount, controlplane.FeatureCorpusExtensions}}
	lab.request(platform, "POST", "/v1/system-images", "image", image, 201, nil)
	builder := controlplane.HarnessReference{Name: "agentcapsule-corpus-builder", Version: "1.0.0"}
	staging := filepath.Join(lab.root, "corpus-staging")
	cache := filepath.Join(lab.root, "corpora")
	if err = lab.worker.EnableCorpusCache(cache); err != nil {
		t.Fatal(err)
	}
	lim := corpussource.Limits{ArchiveBytes: 64 << 20, LFSBytes: 64 << 20, LFSObjects: 8}
	gitHub, err := corpussource.New(policy, lim)
	if err != nil {
		t.Fatal(err)
	}
	download, err := NewCorpusFetcher(corpusFetchStore{lab.store, "local", builder.Name + "@" + builder.Version}, gitHub, lab.accounts, staging, "builder-source")
	if err != nil {
		t.Fatal(err)
	}
	transit := lab.worker.transit.Load()
	catalog, err := controlplane.NewAgentCatalogWithTransit(lab.accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	guest := corpusGuest{w: lab.worker, source: &CorpusSources{Staging: staging, Cache: cache, Limits: lim, MaxImageMiB: 64}, harness: builder, resources: controlplane.AgentResources{VCPUs: 2, MemoryMiB: 1024, DataVolumeMiB: 1024}, catalog: catalog, transit: transit, inspection: inspect}
	var credential controlplane.SourceCredential
	lab.request(owner(), "POST", "/v1/source-credentials", "credential", controlplane.CreateSourceCredentialInput{Name: "fixture", Kind: "github", Host: "github.com", Secret: token}, 201, &credential)
	var corpus controlplane.Corpus
	lab.request(owner(), "POST", "/v1/corpora", "declare", controlplane.CreateCorpusInput{Name: "orion", Source: controlplane.CorpusSource{Kind: "github", URL: "https://github.com/" + fixture.Repository, Ref: "main", CredentialID: credential.ID}}, 201, &corpus)
	t.Cleanup(func() {
		var id string
		if e := lab.db.QueryRow(context.Background(), "SELECT id FROM agents WHERE kind='corpus_builder'").Scan(&id); e == nil {
			ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			_ = lab.worker.host.Retire(ctx, id, ^uint64(0))
		}
	})
	build := func(key string, warm bool) controlplane.CorpusBuild {
		t.Helper()
		var job controlplane.CorpusBuild
		input := controlplane.RequestCorpusBuildInput{Commit: fixture.Commit}
		if tokenPath != "" && !warm {
			input = controlplane.RequestCorpusBuildInput{Ref: "main"}
		}
		lab.request(owner(), "POST", "/v1/corpora/"+corpus.ID+"/builds", key, input, 202, &job)
		watch := beginCorpusWatch(t, cli, job.ID)
		if worked, err := download.FetchOne(ctx); err != nil || !worked {
			t.Fatal("download", worked, err)
		}
		last := ""
		lab.awaitFor("corpus guest", true, 8*time.Minute, func() bool {
			if _, e := guest.one(ctx); e != nil {
				t.Fatal("guest phase", e)
			}
			lab.request(owner(), "GET", "/v1/corpus-builds/"+job.ID, "", nil, 200, &job)
			if job.State != last {
				t.Log(key, job.State, job.ErrorCode)
				last = job.State
				if job.State == "PACKAGING" {
					watch.conversion(t, fixture.PDF)
				}
			}
			switch job.State {
			case "REVIEW":
				return true
			case "FAILED", "CANCELED", "EXPIRED":
				var opStatus, opCode string
				e := lab.db.QueryRow(ctx, `SELECT coalesce(o.status,''),coalesce(o.error_code,'') FROM corpus_builds b LEFT JOIN platform_operations o ON o.id=b.invocation_id WHERE b.id=$1`, job.ID).Scan(&opStatus, &opCode)
				t.Fatalf("failed corpus %s, phase operation %s %s (lookup %v)", job.ErrorCode, opStatus, opCode, e)
			}
			return false
		})
		watch.review(t, lab, reviewer(), job.ID, fixture.PDF)
		raw := lab.request(owner(), "GET", "/v1/corpus-builds/"+job.ID+"/review-file?path=report.json", "", nil, 200, nil)
		report, err := corpusmeta.ParseReport(raw)
		if err != nil || report.BuildID != job.ID || report.Commit != fixture.Commit || job.ArchiveBytes != fixture.Bytes || report.Totals.Failed != 0 {
			t.Fatal("review report", err, report.Totals)
		}
		expected := "converted"
		if warm {
			expected = "cached"
		}
		i := slices.IndexFunc(report.Files, func(f corpusmeta.ReportEntry) bool { return f.Path == fixture.PDF && f.Status == expected })
		if i < 0 {
			t.Fatal("PDF conversion", report.Totals, expected)
		}
		doc := report.Files[i]
		preview := lab.request(owner(), "GET", "/v1/corpus-builds/"+job.ID+"/review-file?path=docs/"+doc.DocID+"/README.md", "", nil, 200, nil)
		if doc.Tokens < 1 || len(bytes.TrimSpace(preview)) == 0 {
			t.Fatal("missing native PDF review")
		}
		var cost map[string]*int64
		if err := json.Unmarshal(job.Costs, &cost); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"llm_calls", "input_tokens", "output_tokens", "audio_seconds", "pages", "cost_micros"} {
			if n := cost[key]; n == nil || *n != 0 {
				t.Fatal("unexpected provider meter", key)
			}
		}
		var sourceOK bool
		err = lab.db.QueryRow(ctx, `SELECT source_drive->>'sha256'=$2 AND lfs_drive IS NULL AND pointers='[]'::jsonb FROM corpus_builds WHERE id=$1`, job.ID, fixture.SHA256).Scan(&sourceOK)
		if err != nil || !sourceOK {
			t.Fatal("source descriptor or unexpected LFS", err)
		}
		var calls int
		err = lab.db.QueryRow(ctx, `SELECT count(*) FROM llm_usage WHERE agent_id=(SELECT builder_agent_id FROM corpus_builds WHERE id=$1)`, job.ID).Scan(&calls)
		if err != nil {
			t.Fatal(err)
		}
		if calls != 0 {
			t.Fatal("text-native PDF invoked a provider", calls)
		}
		t.Logf("%s digest=%s converted=%d cached=%d calls=%d costs=%s", key, job.ImageDigest, report.Totals.Converted, report.Totals.Cached, calls, job.Costs)
		return job
	}
	cold := build("cold", false)
	warm := build("warm", true)
	if cold.ImageDigest != warm.ImageDigest {
		t.Fatal("cold and warm images differ")
	}
	var published controlplane.CorpusRelease
	lab.request(owner(), "POST", "/v1/corpus-builds/"+cold.ID+"/publish", "publish", map[string]int{"version": 1}, 201, &published)
	var extension controlplane.CorpusExtension
	if signed != "" {
		extension = runCourseEnrichment(t, lab, owner, guest, warm, signer)
	}
	validateCorpusDeployment(t, lab, owner, image, cold, warm, published, extension)
}

func runCourseEnrichment(t *testing.T, lab *productPeerLab, owner func() string, guest corpusGuest, review controlplane.CorpusBuild, signer string) controlplane.CorpusExtension {
	t.Helper()
	var authorized controlplane.CorpusEnricher
	lab.request(owner(), "POST", "/v1/corpus-enrichers", "authorize", controlplane.AuthorizeCorpusEnricherInput{Name: "tutor", Harness: controlplane.HarnessReference{Name: "course-enricher", Version: "1.0.0"}}, 201, &authorized)
	if authorized.Signer != signer {
		t.Fatal("authorized publisher differs")
	}
	var ext controlplane.CorpusExtension
	lab.request(owner(), "POST", "/v1/corpus-builds/"+review.ID+"/extensions", "generate", controlplane.RequestCorpusExtensionInput{EnricherID: authorized.ID}, 202, &ext)
	ctx := t.Context()
	t.Cleanup(func() {
		var agent string
		if err := lab.db.QueryRow(context.Background(), "SELECT agent_id FROM corpus_extensions WHERE id=$1", ext.ID).Scan(&agent); err == nil {
			ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			_ = lab.worker.host.Retire(ctx, agent, ^uint64(0))
		}
	})
	lab.awaitFor("signed enrichment", true, 4*time.Minute, func() bool {
		if _, err := guest.enrichOne(ctx); err != nil {
			t.Fatal("enrich", err)
		}
		lab.request(owner(), "GET", "/v1/corpus-extensions/"+ext.ID, "", nil, 200, &ext)
		switch ext.State {
		case "FAILED", "CANCELED", "EXPIRED":
			t.Fatal(ext.State, ext.ErrorCode)
		case "READY":
			return true
		}
		return false
	})
	if ext.ImageBytes < 1 || ext.Digest == review.ImageDigest || !harnesspkg.ValidDigest(ext.Digest) {
		t.Fatal("extension image", ext)
	}
	t.Log("signed review enrichment ready", ext.Name, ext.Digest)
	return ext
}

func validateCorpusDeployment(t *testing.T, lab *productPeerLab, owner func() string, image controlplane.SystemImage, cold, warm controlplane.CorpusBuild, release controlplane.CorpusRelease, extension controlplane.CorpusExtension) {
	t.Helper()
	ctx := t.Context()
	spec := controlplane.TemplateSpec{Name: "classroom", SystemImage: image.ID, Harness: controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}, Corpora: []controlplane.CorpusBinding{{Name: release.Name, Version: 1, Mount: "lessons"}}}
	var tmpl controlplane.TemplateRevision
	lab.request(owner(), "POST", "/v1/templates", "readers", spec, 201, &tmpl)
	var plan controlplane.DeploymentPlan
	lab.request(owner(), "POST", "/v1/deployment-plans", "plan", controlplane.DeploymentRequest{Template: tmpl.Reference, Count: 3, ActiveCount: 0}, 201, &plan)
	if !plan.Admitted {
		t.Fatal("plan refused", plan.Checks)
	}
	lab.request(owner(), "POST", "/v1/deployment-plans/"+plan.ID+"/apply", "deploy", struct{}{}, 202, nil)
	rows, err := lab.db.Query(ctx, "SELECT agent_id FROM agent_deployment_members WHERE deployment_id=$1 ORDER BY ordinal", plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	var agents []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		agents = append(agents, id)
		lab.peers = append(lab.peers, &productPeer{agent: controlplane.AgentCreation{AgentID: id}})
	}
	rows.Close()
	if len(agents) != 3 || rows.Err() != nil {
		t.Fatal("deployed agents", len(agents), rows.Err())
	}
	lab.awaitFor("provision classroom", true, 5*time.Minute, func() bool {
		var n int
		if err := lab.db.QueryRow(ctx, "SELECT count(*) FROM agents WHERE id=ANY($1) AND phase='LIVE'", agents).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == len(agents)
	})
	lab.request(owner(), "POST", "/v1/corpus-builds/"+warm.ID+"/try", "try", controlplane.TryCorpusInput{AgentID: agents[0], Mount: "trial"}, 200, nil)
	check := func(agent, mount string) {
		t.Helper()
		var view controlplane.AgentCorpora
		lab.request(owner(), "GET", "/v1/agents/"+agent+"/corpora", "", nil, 200, &view)
		if len(view.Corpora) != 1 || view.Corpora[0].Mount != mount || view.Corpora[0].Digest != cold.ImageDigest {
			t.Fatal("mount", len(view.Corpora), mount)
		}
	}
	check(agents[0], "trial")
	var probe controlplane.AgentCreation
	lab.request(owner(), "POST", "/v1/agents/"+agents[0]+"/wake", "wake-trial", struct{}{}, 202, &probe)
	lab.awaitOperation(owner, probe.OperationID)
	lab.request(owner(), "POST", "/v1/agents/"+agents[0]+"/sleep", "sleep-trial", struct{}{}, 202, &probe)
	lab.awaitOperation(owner, probe.OperationID)
	var released controlplane.CorpusRelease
	lab.request(owner(), "POST", "/v1/corpus-builds/"+warm.ID+"/publish", "publish-again", map[string]int{"version": 2}, 201, &released)
	if extension.ID != "" && (len(released.Extensions) != 1 || released.Extensions[0].Name != extension.Name || released.Extensions[0].Digest != extension.Digest) {
		t.Fatal("release extension snapshot", released.Extensions)
	}
	spec.Corpora = []controlplane.CorpusBinding{{Name: released.Name, Version: 2, Mount: "orion"}}
	var revision controlplane.TemplateRevision
	lab.request(owner(), "POST", "/v1/templates", "next", spec, 201, &revision)
	var rollout controlplane.Rollout
	lab.request(owner(), "POST", "/v1/deployments/"+plan.ID+"/rollouts", "rollout", controlplane.RolloutInput{Template: revision.Reference, MaxUnavailable: 1}, 202, &rollout)
	lab.awaitFor("rollout", true, 6*time.Minute, func() bool {
		lab.request(owner(), "GET", "/v1/rollouts/"+rollout.ID, "", nil, 200, &rollout)
		if rollout.Status == "paused" {
			t.Fatal("rollout paused", rollout.Reason)
		}
		return rollout.Status == "completed"
	})
	if rollout.Updated != 3 {
		t.Fatal("rollout members", rollout)
	}
	cached := filepath.Join(lab.worker.corpusCache.dir(cold.ImageDigest), corpuspkg.ImageFile)
	disk, err := os.Stat(cached)
	if err != nil {
		t.Fatal(err)
	}
	// All three readers are woken together so the assertion observes three
	// jails hard-linking the same immutable inode.
	for _, id := range agents {
		check(id, "orion")
		var op controlplane.AgentCreation
		lab.request(owner(), "POST", "/v1/agents/"+id+"/wake", "wake-"+id, struct{}{}, 202, &op)
		lab.awaitOperation(owner, op.OperationID)
	}
	runs := lab.runs(3)
	for _, id := range agents {
		jail := filepath.Join(lab.root, "jails", "firecracker", runs[id].ID, "root")
		linked, err := os.Stat(filepath.Join(jail, "corpus0.ext4"))
		if err != nil || !os.SameFile(disk, linked) {
			t.Fatal("shared release inode", err)
		}
		if extension.ID != "" {
			expected, err := os.Stat(filepath.Join(lab.worker.corpusCache.dir(extension.Digest), corpuspkg.ImageFile))
			if err != nil {
				t.Fatal(err)
			}
			ext, err := os.Stat(filepath.Join(jail, "corpus1.ext4"))
			if err != nil || !os.SameFile(expected, ext) {
				t.Fatal("shared extension inode", err)
			}
		}
	}
	t.Log("3 agents bind and boot the same release after the rollout", rollout.Status)
}
