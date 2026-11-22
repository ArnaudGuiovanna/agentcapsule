package controlplane

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/golang-jwt/jwt/v5"
)

// The runs of spec/corpus_lifecycle.qnt across two organizations (audit
// finding A-10 closed their pending projections): o1 owns l.agent (a1), o2
// owns a second agent (a2). Corpora are named per organization, and the
// host's image cache is keyed by digest: two organizations that build the
// same bytes share one file.
type corpusOrganizations struct {
	*invocationLab
	other      Principal // o2's owner
	otherAgent string    // a2
}

func newCorpusOrganizations(t *testing.T) *corpusOrganizations {
	t.Helper()
	l := newInvocationLab(t)
	ctx := t.Context()
	image := SystemImage{ID: "mount@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("a", 64)}, Features: []string{FeatureCorpusMount}}
	if err := l.s.ReportDeploymentHost(ctx, "local", HostProvisioningBudget{MaxActive: 8, VCPUs: 16, MemoryMiB: 16384, UIDSlots: 1000}, []ImageDigests{image.ImageDigests}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.c.ApproveSystemImage(ctx, l.platform, "image", image); err != nil {
		t.Fatal(err)
	}
	// o2: its own trust for the same issuer, under another audience.
	org := createTestOrganization(t, l.a, l.platform, "corpus-o2")
	trust := l.trust
	trust.TenantID, trust.Audience = org.ID, "o2"
	installed, err := l.s.ChangeDelegationAuthority(ctx, DelegationChange{OperationID: "o2-trust", Actor: "test-operator", Action: "install", TenantID: org.ID, Issuer: trust.Issuer, Audience: trust.Audience, Trust: &trust})
	if err != nil {
		t.Fatal(err)
	}
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust, trust}})
	if err != nil {
		t.Fatal(err)
	}
	waitTenantClock(t, l.s, installed.MinimumIAT)
	other, err := l.s.AuthenticateDelegation(ctx, v, l.sign(t, newID("jti"), installed.MinimumIAT, func(c jwt.MapClaims) { c["aud"] = "o2"; c["scope"] = agentScopes }))
	if err != nil || other.TenantID != org.ID {
		t.Fatal("o2's owner", err)
	}
	o := &corpusOrganizations{invocationLab: l, other: other, otherAgent: activateTenantAgent(t, l.tenantLab, l.c, other, "o2-consumer")}
	for _, agent := range []string{l.agent, o.otherAgent} {
		if _, err = l.s.pool.Exec(ctx, "UPDATE agent_specs SET system_image=$2 WHERE agent_id=$1", agent, image.ID); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

// review declares a corpus of p's organization (once per name) and finishes
// one build of it: the worker moves its image, of digest d, into the cache and
// the build turns REVIEW (finish in the model).
func (o *corpusOrganizations) review(t *testing.T, p Principal, name, key, digest string) string {
	t.Helper()
	ctx := t.Context()
	var corpus string
	err := o.s.pool.QueryRow(ctx, "SELECT id FROM corpora WHERE tenant_id=$1 AND name=$2", p.TenantID, name).Scan(&corpus)
	if err != nil {
		r, err := o.a.CreateCorpus(ctx, p, "declare-"+key, CreateCorpusInput{Name: name, Source: CorpusSource{Kind: "github", URL: "https://github.com/school/" + name, Ref: "main"}})
		var c Corpus
		if err != nil || json.Unmarshal(r.Body, &c) != nil {
			t.Fatal("declare", name, err)
		}
		corpus = c.ID
	}
	r, err := o.a.RequestCorpusBuild(ctx, p, corpus, key, RequestCorpusBuildInput{Commit: strings.Repeat("a", 40)})
	var b CorpusBuild
	if err != nil || json.Unmarshal(r.Body, &b) != nil {
		t.Fatal("build", name, err)
	}
	if _, err = o.s.pool.Exec(ctx, "UPDATE corpus_builds SET state='PACKAGING',host_id='local',builder='builder@1',lease_token='token',lease_until=now()+interval '1 hour' WHERE id=$1", b.ID); err != nil {
		t.Fatal(err)
	}
	if err = o.tr.CompleteCorpusReview(ctx, CorpusWork{ID: b.ID, Token: "token", Phase: "PACKAGING"}, CorpusResult{Digest: digest, UUID: "11111111-1111-1111-1111-111111111111", Bytes: 8192, Files: map[string][]byte{"INDEX.md": []byte("index"), "report.json": []byte("{}")}}); err != nil {
		t.Fatal("review", name, err)
	}
	return b.ID
}

func (o *corpusOrganizations) publish(t *testing.T, p Principal, build, key string) CorpusRelease {
	t.Helper()
	r, err := o.a.PublishCorpusBuild(t.Context(), p, build, key, 1)
	var rel CorpusRelease
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &rel) != nil {
		t.Fatal("publish", err)
	}
	return rel
}

func (o *corpusOrganizations) pins(t *testing.T) []string {
	t.Helper()
	pins, err := o.s.CorpusImagesInUse(t.Context(), "local")
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

// crossOrganizationBindingRefusedTest: o2 publishes c2:1 of build b3. Neither
// a binding nor a template of o1 can name it, nor can o1 try b3; o2's own
// agent binds it and its next boot mounts the image.
func TestCrossOrganizationBindingRefused(t *testing.T) {
	o := newCorpusOrganizations(t)
	ctx := t.Context()
	digest := "sha256:" + strings.Repeat("d", 64)
	b3 := o.review(t, o.other, "atlas", "b3", digest)
	o.publish(t, o.other, b3, "c2-1")
	foreign := []CorpusBinding{{Name: "atlas", Version: 1}}
	// not(bindable(a1, c2:1)): the name is unknown in o1.
	if _, err := o.a.SetAgentCorpora(ctx, o.owner, o.agent, "a1-binds-c2", foreign); !errors.Is(err, ErrCorpusUnavailable) {
		t.Fatal("o1 bound o2's release", err)
	}
	spec := TemplateSpec{Name: "foreign-corpus", SystemImage: "mount@1", Harness: HarnessReference{"reference", "1.0.0"}, Resources: AgentResources{1, 256, 64}, Capabilities: []string{}, Corpora: foreign}
	if _, err := o.c.PublishTemplate(ctx, o.owner, "a1-template-c2", spec); !errors.Is(err, ErrCorpusUnavailable) {
		t.Fatal("o1's template named o2's release", err)
	}
	// not(triable(a1, b3)): the build is unknown in o1, and o2 cannot try it
	// on o1's agent either.
	if _, err := o.a.TryCorpusBuild(ctx, o.owner, b3, "a1-tries-b3", TryCorpusInput{AgentID: o.agent}); !errors.Is(err, ErrNotFound) {
		t.Fatal("o1 tried o2's build", err)
	}
	if _, err := o.a.TryCorpusBuild(ctx, o.other, b3, "a1-tried-by-o2", TryCorpusInput{AgentID: o.agent}); err == nil {
		t.Fatal("o2 tried its build on o1's agent")
	}
	if discs, err := o.s.BootCorpora(ctx, o.agent, "local"); err != nil || len(discs) != 0 {
		t.Fatal("a refused binding reached a1's boot", discs, err)
	}
	// bind(a2, c2:1).then(boot(a2)): mounted == {(c2:1, d1)}.
	if _, err := o.a.SetAgentCorpora(ctx, o.other, o.otherAgent, "a2-binds-c2", foreign); err != nil {
		t.Fatal(err)
	}
	discs, err := o.s.BootCorpora(ctx, o.otherAgent, "local")
	if err != nil || len(discs) != 1 || discs[0].Digest != digest || discs[0].Mount != "atlas" {
		t.Fatal("a2's boot", discs, err)
	}
}

// sharedDigestStaysWhileEitherPinsItTest: o1 and o2 build the same bytes
// (d1), publish c1:1 and c2:1, a2 binds c2:1, and o1 deprecates c1:1: the
// image stays in the cache. Once o2 lets it go too, nothing keeps it.
func TestSharedDigestStaysWhileEitherPinsIt(t *testing.T) {
	o := newCorpusOrganizations(t)
	ctx := t.Context()
	digest := "sha256:" + strings.Repeat("e", 64)
	b1 := o.review(t, o.owner, "course", "b1", digest)
	b3 := o.review(t, o.other, "course", "b3", digest)
	c11 := o.publish(t, o.owner, b1, "c1-1")
	c21 := o.publish(t, o.other, b3, "c2-1")
	if c11.ID == c21.ID || c11.Digest != c21.Digest {
		t.Fatal("two organizations' releases of the same bytes", c11, c21)
	}
	if _, err := o.a.SetAgentCorpora(ctx, o.other, o.otherAgent, "a2-binds-c2", []CorpusBinding{{Name: "course", Version: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.a.DeprecateCorpusRelease(ctx, o.owner, c11.ID, "deprecate-c1"); err != nil {
		t.Fatal(err)
	}
	// One file for both organizations, still pinned: not(evictable(d1)).
	if pins := o.pins(t); !slices.Equal(pins, []string{digest}) {
		t.Fatal("o1's deprecation released an image o2 pins", pins)
	}
	// The pin was o2's: once a2 unbinds and o2 deprecates c2:1, nothing keeps d1.
	if _, err := o.a.SetAgentCorpora(ctx, o.other, o.otherAgent, "a2-unbinds", []CorpusBinding{}); err != nil {
		t.Fatal(err)
	}
	if pins := o.pins(t); !slices.Equal(pins, []string{digest}) {
		t.Fatal("o2's active release no longer pins its image", pins)
	}
	if _, err := o.a.DeprecateCorpusRelease(ctx, o.other, c21.ID, "deprecate-c2"); err != nil {
		t.Fatal(err)
	}
	if pins := o.pins(t); len(pins) != 0 {
		t.Fatal("an image nothing pins is kept", pins)
	}
}
