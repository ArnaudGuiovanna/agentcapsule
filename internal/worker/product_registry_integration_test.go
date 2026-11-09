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

// Two tenant agents run a harness imported from an OCI registry: the package
// is pulled, verified and cached once, both VMs read the same read-only image,
// and each guest runs the harness from that drive. Nothing is built on the host.
func TestProductWorkerTenantRunsAnImportedHarness(t *testing.T) {
	lab := newProductPeerLab(t)
	reg := registrytest.New()
	t.Cleanup(reg.Close)
	rule := ociregistry.Rule{Host: reg.Host(), Repositories: []string{"acme/"}, Local: true}

	// Publish the reference harness as a registry package, at a path that does
	// not exist in the platform image: only the harness drive can provide it.
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "opt/echo"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyExecutable(t, filepath.Join(filepath.Dir(config(t).Initrd), "capsule-echo"), filepath.Join(src, "opt/echo/harness"))
	m := harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: "echo-oci", Version: "1.0.0", Protocol: harnesspkg.Protocol,
		Architecture: harnesspkg.Architecture, Base: harnesspkg.GuestBase, Entrypoint: []string{"/opt/echo/harness"}}
	pkg := t.TempDir()
	if err := harnesspkg.BuildRootfs(t.Context(), m, src, filepath.Join(pkg, harnesspkg.RootfsFile), 64); err != nil {
		t.Fatal(err)
	}
	if err := harnesspkg.WritePackage(pkg, m); err != nil {
		t.Fatal(err)
	}
	ref, err := ociregistry.Push(t.Context(), rule, "acme/echo", "1.0.0", pkg)
	if err != nil {
		t.Fatal(err)
	}

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
	var imp controlplane.HarnessImport
	lab.request(platform, "POST", "/v1/harness-imports", "echo-oci", controlplane.HarnessImportInput{Reference: ref.String()}, 202, &imp)
	if worked, err := importer.ImportOne(t.Context()); err != nil || !worked {
		t.Fatal("import", worked, err)
	}
	lab.request(platform, "GET", "/v1/harness-imports/"+imp.ID, "", nil, 200, &imp)
	if imp.State != "READY" {
		t.Fatal("import not ready", imp.State, imp.ErrorCode)
	}

	owner := func() string { return id.token(t, "alice") }
	var agents []controlplane.AgentCreation
	for _, name := range []string{"oci-a", "oci-b"} {
		var created controlplane.AgentCreation
		in := controlplane.CreateAgentInput{Name: name, Harness: controlplane.HarnessReference{Name: "echo-oci", Version: "1.0.0"},
			Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}
		lab.request(owner(), "POST", "/v1/agents", "agent-"+name, in, 202, &created)
		lab.peers = append(lab.peers, &productPeer{agent: created})
		lab.awaitOperation(owner, created.OperationID)
		agents = append(agents, created)
	}
	var bob controlplane.Member
	lab.request(owner(), "POST", "/v1/members", "bob", controlplane.CreateMemberInput{Issuer: id.trust.Issuer, Subject: "bob", DisplayName: "Bob", Role: "agent_user"}, 201, &bob)
	for _, a := range agents {
		lab.request(owner(), "POST", "/v1/agents/"+a.AgentID+"/assignments", "assign-"+a.AgentID,
			controlplane.CreateAssignmentInput{PrincipalID: bob.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, 201, nil)
		var wake controlplane.AgentCreation
		lab.request(owner(), "POST", "/v1/agents/"+a.AgentID+"/wake", "wake-"+a.AgentID, map[string]any{}, 202, &wake)
		lab.awaitOperation(owner, wake.OperationID)
	}

	// Both VMs read the cached image through hard links: one inode, read-only.
	runs := lab.runs(2)
	cached, err := os.Stat(filepath.Join(importer.PackageDir(ref.Digest), harnesspkg.RootfsFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range agents {
		jail := filepath.Join(lab.root, "jails", "firecracker", runs[a.AgentID].ID, "root")
		linked, err := os.Stat(filepath.Join(jail, "harness.ext4"))
		if err != nil || !os.SameFile(cached, linked) {
			t.Fatal("the VM does not share the cached harness image", a.AgentID, err)
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

	// Each guest answers from the imported harness.
	bobToken := func() string { return id.token(t, "bob") }
	for _, a := range agents {
		var inv controlplane.Invocation
		lab.request(bobToken(), "POST", "/v1/agents/"+a.AgentID+"/invocations", "inv-"+a.AgentID, map[string]any{
			"content": []map[string]string{{"type": "text", "text": "hello from " + a.AgentID}}}, 202, &inv)
		lab.await("invocation "+a.AgentID, true, func() bool {
			var v controlplane.Invocation
			lab.request(bobToken(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
			if v.State == "failed" || v.State == "canceled" || v.State == "expired" {
				t.Fatal("invocation ended without an answer", v.State, v.ErrorCode)
			}
			return v.State == "completed"
		})
		result := string(lab.request(bobToken(), "GET", "/v1/invocations/"+inv.ID+"/result", "", nil, 200, nil))
		if !strings.Contains(result, "hello from "+a.AgentID) {
			t.Fatal("unexpected answer from the imported harness")
		}
	}
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
