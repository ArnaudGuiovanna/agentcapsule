//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/registrytest"
)

// registryLab is a product lab with an in-process OCI registry, an importer
// attached to the worker, one organization (owner alice) and member bob.
type registryLab struct {
	*productPeerLab
	rule     ociregistry.Rule
	importer *HarnessImporter
	id       *tenantIdentity
	platform string
	bob      controlplane.Member
}

func newRegistryLab(t *testing.T) *registryLab {
	t.Helper()
	lab := newProductPeerLab(t)
	reg := registrytest.New()
	t.Cleanup(reg.Close)
	rule := ociregistry.Rule{Host: reg.Host(), Repositories: []string{"acme/"}, Local: true}
	fetcher, err := ociregistry.NewFetcher(ociregistry.Policy{Rules: []ociregistry.Rule{rule}}, 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	importer, err := NewHarnessImporter(lab.store, fetcher, filepath.Join(lab.root, "releases"), "kvm-importer")
	if err != nil {
		t.Fatal(err)
	}
	if err = lab.worker.EnableRegistry(importer); err != nil {
		t.Fatal(err)
	}
	id, _, platform := lab.installTenant(t)
	l := &registryLab{productPeerLab: lab, rule: rule, importer: importer, id: id, platform: platform}
	lab.request(l.owner(), "POST", "/v1/members", "bob", controlplane.CreateMemberInput{Issuer: id.trust.Issuer, Subject: "bob", DisplayName: "Bob", Role: "agent_user"}, 201, &l.bob)
	return l
}

func (l *registryLab) owner() string { return l.id.token(l.t, "alice") }
func (l *registryLab) user() string  { return l.id.token(l.t, "bob") }

// publish packs the reference echo harness at dir inside the image, at a path
// that does not exist in the platform image (only the harness drive can
// provide it), pushes it as echo-oci:version and imports it.
func (l *registryLab) publish(version, dir string) ociregistry.Reference {
	t := l.t
	t.Helper()
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, dir), 0o755); err != nil {
		t.Fatal(err)
	}
	copyExecutable(t, filepath.Join(filepath.Dir(config(t).Initrd), "capsule-echo"), filepath.Join(src, dir, "harness"))
	m := harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: "echo-oci", Version: version, Protocol: harnesspkg.Protocol,
		Architecture: harnesspkg.Architecture, Base: harnesspkg.GuestBase, Entrypoint: []string{"/" + dir + "/harness"}}
	pkg := t.TempDir()
	if err := harnesspkg.BuildRootfs(t.Context(), m, src, filepath.Join(pkg, harnesspkg.RootfsFile), 64); err != nil {
		t.Fatal(err)
	}
	if err := harnesspkg.WritePackage(pkg, m); err != nil {
		t.Fatal(err)
	}
	ref, err := ociregistry.Push(t.Context(), l.rule, "acme/echo", version, pkg)
	if err != nil {
		t.Fatal(err)
	}
	var imp controlplane.HarnessImport
	l.request(l.platform, "POST", "/v1/harness-imports", "echo-oci-"+version, controlplane.HarnessImportInput{Reference: ref.String()}, 202, &imp)
	if worked, err := l.importer.ImportOne(t.Context()); err != nil || !worked {
		t.Fatal("import", worked, err)
	}
	l.request(l.platform, "GET", "/v1/harness-imports/"+imp.ID, "", nil, 200, &imp)
	if imp.State != "READY" {
		t.Fatal("import not ready", imp.State, imp.ErrorCode)
	}
	return ref
}

// create makes a tenant agent on echo-oci:version, assigns it to bob and wakes it.
func (l *registryLab) create(name, version string) controlplane.AgentCreation {
	l.t.Helper()
	var created controlplane.AgentCreation
	in := controlplane.CreateAgentInput{Name: name, Harness: controlplane.HarnessReference{Name: "echo-oci", Version: version},
		Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}
	l.request(l.owner(), "POST", "/v1/agents", "agent-"+name, in, 202, &created)
	l.peers = append(l.peers, &productPeer{agent: created})
	l.awaitOperation(l.owner, created.OperationID)
	l.request(l.owner(), "POST", "/v1/agents/"+created.AgentID+"/assignments", "assign-"+created.AgentID,
		controlplane.CreateAssignmentInput{PrincipalID: l.bob.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, 201, nil)
	l.lifecycle(created.AgentID, "wake", "wake-"+created.AgentID)
	return created
}

func (l *registryLab) lifecycle(agentID, kind, key string) {
	l.t.Helper()
	var op controlplane.AgentCreation
	l.request(l.owner(), "POST", "/v1/agents/"+agentID+"/"+kind, key, map[string]any{}, 202, &op)
	l.awaitOperation(l.owner, op.OperationID)
}

// bootsFrom checks that the agent's current VM reads exactly the cached image
// of ref, through a hard link, attached as a read-only second drive.
func (l *registryLab) bootsFrom(agentID string, ref ociregistry.Reference, vms int) {
	t := l.t
	t.Helper()
	cached, err := os.Stat(filepath.Join(l.importer.PackageDir(ref.Digest), harnesspkg.RootfsFile))
	if err != nil {
		t.Fatal(err)
	}
	jail := filepath.Join(l.root, "jails", "firecracker", l.runs(vms)[agentID].ID, "root")
	linked, err := os.Stat(filepath.Join(jail, "harness.ext4"))
	if err != nil || !os.SameFile(cached, linked) {
		t.Fatal("the VM does not boot the expected cached harness image", agentID, ref.Tag, err)
	}
	var cfg struct {
		Drives []struct {
			ID       string `json:"drive_id"`
			ReadOnly bool   `json:"is_read_only"`
		} `json:"drives"`
	}
	raw, err := os.ReadFile(filepath.Join(jail, "config.json"))
	if err != nil || json.Unmarshal(raw, &cfg) != nil || len(cfg.Drives) != 2 || cfg.Drives[1].ID != "harness" || !cfg.Drives[1].ReadOnly {
		t.Fatal("harness drive not attached read-only", string(raw), err)
	}
}

// answers sends bob's text to the agent and checks the harness echoes it.
func (l *registryLab) answers(agentID, key, text string) {
	t := l.t
	t.Helper()
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agentID+"/invocations", key, map[string]any{
		"content": []map[string]string{{"type": "text", "text": text}}}, 202, &inv)
	l.await("invocation "+key, true, func() bool {
		var v controlplane.Invocation
		l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
		if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
			t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
		}
		return v.State == "completed"
	})
	result := string(l.request(l.user(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil))
	if !strings.Contains(result, text) {
		t.Fatal("unexpected answer from the imported harness")
	}
}

// Two tenant agents run a harness imported from an OCI registry: the package
// is pulled, verified and cached once, both VMs read the same read-only image,
// and each guest runs the harness from that drive. Nothing is built on the host.
func TestProductWorkerTenantRunsAnImportedHarness(t *testing.T) {
	l := newRegistryLab(t)
	ref := l.publish("1.0.0", "opt/echo")
	a, b := l.create("oci-a", "1.0.0"), l.create("oci-b", "1.0.0")
	for _, agent := range []controlplane.AgentCreation{a, b} {
		l.bootsFrom(agent.AgentID, ref, 2)
		l.answers(agent.AgentID, "inv-"+agent.AgentID, "hello from "+agent.AgentID)
	}
}

// An agent is upgraded to another imported release and rolled back, keeping
// its encrypted data volume: each change applies at the next boot, the guest
// then runs the other image, and answers. Once the upgrade is deprecated and no
// agent of the host can boot it, its package leaves the cache; the release the
// agent runs stays.
func TestProductWorkerTenantUpgradesAndRollsBackAnImportedHarness(t *testing.T) {
	l := newRegistryLab(t)
	v1 := l.publish("1.0.0", "opt/echo")
	v2 := l.publish("2.0.0", "opt/echo2")
	agent := l.create("upgraded", "1.0.0").AgentID
	l.bootsFrom(agent, v1, 1)
	l.answers(agent, "before", "before the upgrade")

	change := func(version, key string) controlplane.AgentRelease {
		var out controlplane.AgentRelease
		l.request(l.owner(), "POST", "/v1/agents/"+agent+"/release", key,
			controlplane.ReleaseChange{Harness: controlplane.HarnessReference{Name: "echo-oci", Version: version}}, 200, &out)
		if out.Harness.Version != version || out.Applies != "next_boot" {
			t.Fatalf("release change %+v", out)
		}
		return out
	}
	// Upgrade: the running VM keeps its harness until it restarts.
	if up := change("2.0.0", "upgrade"); up.Previous.Version != "1.0.0" {
		t.Fatalf("upgrade %+v", up)
	}
	l.bootsFrom(agent, v1, 1)
	l.lifecycle(agent, "sleep", "sleep-1")
	l.lifecycle(agent, "wake", "wake-2")
	l.bootsFrom(agent, v2, 1)
	l.answers(agent, "after-upgrade", "after the upgrade")

	// Rollback.
	change("1.0.0", "rollback")
	l.lifecycle(agent, "sleep", "sleep-2")
	l.lifecycle(agent, "wake", "wake-3")
	l.bootsFrom(agent, v1, 1)
	l.answers(agent, "after-rollback", "after the rollback")

	// Deprecating 2.0.0 frees its package; 1.0.0, which the agent runs, stays.
	var releases struct {
		Items []controlplane.HarnessRelease `json:"items"`
	}
	l.request(l.platform, "GET", "/v1/harness-releases", "", nil, 200, &releases)
	for _, r := range releases.Items {
		if r.Name == "echo-oci" && r.Version == "2.0.0" {
			l.request(l.platform, "POST", "/v1/harness-releases/"+r.ID+"/deprecate", "deprecate-2", map[string]any{}, 200, nil)
		}
	}
	l.request(l.owner(), "POST", "/v1/agents/"+agent+"/release", "to-deprecated",
		controlplane.ReleaseChange{Harness: controlplane.HarnessReference{Name: "echo-oci", Version: "2.0.0"}}, 422, nil)
	evicted, err := l.importer.Evict(t.Context())
	if err != nil || len(evicted) != 1 || evicted[0] != v2.Digest {
		t.Fatal("eviction", evicted, err)
	}
	if _, err = os.Stat(l.importer.PackageDir(v1.Digest)); err != nil {
		t.Fatal("the running release was evicted", err)
	}
	l.answers(agent, "after-eviction", "after the eviction")
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
}
