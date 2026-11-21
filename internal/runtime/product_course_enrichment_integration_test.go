//go:build linux && cgo && kvm_integration && kvm_product_integration

package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/registrytest"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// This test uses the packaged demonstration harness, the product guest and
// its normal authenticated vsock control/platform channels.
type coursePlatform struct {
	capsuleprotocol.PlatformAPI
	completed chan capsuleprotocol.InvocationCompletion
}

func (p *coursePlatform) Validate(context.Context) error { return nil }
func (p *coursePlatform) CompleteInvocation(ctx context.Context, key string, in capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error) {
	if key == "" || in.Validate() != nil {
		return capsuleprotocol.CompletionReceipt{}, errors.New("invalid receipt")
	}
	select {
	case p.completed <- in:
	case <-ctx.Done():
		return capsuleprotocol.CompletionReceipt{}, ctx.Err()
	}
	return capsuleprotocol.CompletionReceipt{OperationID: in.OperationID, State: "SUCCEEDED"}, nil
}
func TestProductCourseEnrichmentKVM(t *testing.T) {
	pkg := os.Getenv("AGENTCAPSULE_KVM_COURSE_ENRICHER")
	if pkg == "" {
		t.Fatal("AGENTCAPSULE_KVM_COURSE_ENRICHER must name a course-enricher harness package")
	}
	completion := &coursePlatform{completed: make(chan capsuleprotocol.InvocationCompletion, 1)}
	l := newCorpusLab(t, func(opts *FirecrackerOptions) {
		opts.PlatformHandler = func(id string, r VMRun) (http.Handler, error) {
			return capsuleprotocol.NewPlatformHandler(capsuleprotocol.Identity{AgentID: id, Incarnation: r.Incarnation, Generation: r.Generation, VMID: r.ID}, completion)
		}
	})
	// Only the package fetched under a signed-import policy reaches the VM.
	reg := registrytest.New()
	defer reg.Close()
	rule := ociregistry.Rule{Host: reg.Host(), Repositories: []string{"courses/"}, Local: true}
	ref, err := ociregistry.Push(t.Context(), rule, "courses/enricher", "1.0.0", pkg)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	public, err := ociregistry.ParsePublisherKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ociregistry.Sign(t.Context(), rule, ref, signer); err != nil {
		t.Fatal(err)
	}
	rule.Keys = []ociregistry.PublisherKey{public}
	fetcher, err := ociregistry.NewFetcher(ociregistry.Policy{Rules: []ociregistry.Rule{rule}, RequireSignatures: true}, 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	inspection := sandbox.Options{UID: 61999, GID: 61999}
	fetcher.Sandbox = inspection
	verified, err := fetcher.Fetch(t.Context(), ref, t.TempDir())
	if err != nil {
		t.Fatal("signed import", err)
	}
	m := verified.Manifest
	if verified.Signer != public.ID || m.Name != "course-enricher" || m.Base != harnesspkg.GuestBase2 {
		t.Fatal("publisher or manifest", verified.Signer, m)
	}
	t.Log("verified signed harness", ref.Digest)
	// The host and all jails need to hard-link the package and corpus images.
	harness := filepath.Join(l.cache, "enricher.ext4")
	copyFile(t, filepath.Join(verified.Dir, harnesspkg.RootfsFile), harness, 0444)
	h := &HarnessImage{Path: harness, Digest: "sha256:" + hashFile(t, harness), Entrypoint: m.Entrypoint}
	id := l.agent(h)
	baseDir := t.TempDir()
	for _, p := range []string{"ext", "search", "docs/d1"} {
		if err = os.MkdirAll(filepath.Join(baseDir, p), 0755); err != nil {
			t.Fatal(err)
		}
	}
	build := "cbd_" + strings.Repeat("a", 32)
	info := corpuspkg.Info{Schema: corpuspkg.Schema, Name: "maths", Title: "Maths", BuildID: build, Commit: strings.Repeat("a", 40), Builder: "builder@1", Languages: []string{"fr"}, Modalities: []string{"text"}, Tokens: 3, Documents: []corpuspkg.InfoEntry{{ID: "d1", Path: "fractions.md", Title: "Les fractions", Kind: "text", Tokens: 3}}}
	metadata, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for p, b := range map[string][]byte{corpuspkg.InfoFile: metadata, corpuspkg.IndexFile: []byte("Cours de maths\n"), corpuspkg.SearchFile: []byte("fractions"), "docs/d1/README.md": []byte("Fractions\n")} {
		if err = os.WriteFile(filepath.Join(baseDir, p), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	base := CorpusImage{Mount: "base", Path: filepath.Join(l.cache, "math.ext4"), UUID: financeKVM}
	if _, err = corpuspkg.BuildImage(t.Context(), baseDir, base.Path, base.UUID, 32<<20); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base.Path, 0444); err != nil {
		t.Fatal(err)
	}
	base.Digest = "sha256:" + hashFile(t, base.Path)
	output := filepath.Join(l.cache, "output.ext4")
	if err = CreateBuildOutput(output, 32<<20); err != nil {
		t.Fatal(err)
	}
	if err = l.h.SetEnrichmentDrives(t.Context(), id, base, output); err != nil {
		t.Fatal(err)
	}
	if _, err = l.start(id); err != nil {
		t.Fatal("enrichment boot", err)
	}
	input, _ := json.Marshal(map[string]any{"schema": "agentcapsule.corpus-enricher/v1", "build_id": build, "name": "tutor", "mount": "/corpus/base", "uuid": handbookKVM, "output": map[string]int64{"bytes": 32 << 20}})
	event, _ := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op-course", Mandate: capsuleprotocol.InstructionMandate{ID: "grant", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)}, Content: []capsuleprotocol.ContentPart{{Type: "json", JSON: capsuleprotocol.JSONValue(input)}}})
	ctrl, err := l.h.Control(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ctrl.Invoke(t.Context(), harnessstore.Event{ID: "enrichment", Subjects: []string{"agent/" + id, "event/enrichment"}, Body: event})
	if err != nil || !capsuleprotocol.IsWorkingResult(receipt.Result) {
		t.Fatal("working receipt", err, string(receipt.Result))
	}
	var result capsuleprotocol.InvocationCompletion
	select {
	case result = <-completion.completed:
	case <-time.After(90 * time.Second):
		t.Fatal("completion not received")
	}
	l.stop(id)
	if err = l.h.SetEnrichmentDrives(t.Context(), id, CorpusImage{}, ""); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Schema string
		Bytes  int64 `json:"image_bytes"`
	}
	if result.Outcome != "completed" || len(result.Content) != 1 || json.Unmarshal([]byte(result.Content[0].JSON), &reply) != nil || reply.Schema != "agentcapsule.corpus-enricher/v1" || reply.Bytes < 1 || reply.Bytes > 32<<20 {
		t.Fatal("completion", result)
	}
	if err = os.Truncate(output, reply.Bytes); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = corpuspkg.CheckImage(f, reply.Bytes, 32<<20, handbookKVM); err != nil {
		t.Fatal(err)
	}
	if err = corpuspkg.InspectExtension(t.Context(), output, inspection); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(output, 0444); err != nil {
		t.Fatal(err)
	}
	base.Mount = "course"
	extension := CorpusImage{Mount: "tutor", Parent: "course", UUID: handbookKVM, Path: output, Digest: "sha256:" + hashFile(t, output)}
	consumer := l.agent(l.harness(harnesspkg.GuestBase2), base, extension)
	if _, err = l.start(consumer); err != nil {
		t.Fatal("consumer boot", err)
	}
	view := l.probe(consumer)
	l.stop(consumer)
	if len(view.Mounts) != 1 || len(view.Mounts[0].Extensions) != 1 {
		t.Fatal("consumer layout", view)
	}
	ext := view.Mounts[0].Extensions[0]
	if ext.Name != "tutor" || ext.Write != "EROFS" || !slices.Equal(ext.Files, []string{"exercices.json", "notions.json"}) {
		t.Fatal("mounted extension", ext)
	}
	for _, flag := range []string{"ro", "noexec", "nosuid", "nodev"} {
		if !slices.Contains(ext.Options, flag) {
			t.Fatal("mount flag", flag, ext)
		}
	}
}
