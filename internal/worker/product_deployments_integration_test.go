//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// A new worker resumes a partially initialized batch in the same runtime root.
// Each ready volume must have its own inode, LUKS header and enrollment.
func TestProductDeploymentCampaignKVM(t *testing.T) {
	lab := newProductPeerLab(t)
	identity, org, platform := lab.installTenant(t)
	owner := func() string { return identity.token(t, "alice") }
	ctx := t.Context()
	cfg := config(t)
	image := controlplane.SystemImage{ID: "product@1", ImageDigests: controlplane.ImageDigests{Kernel: "sha256:" + digest(t, cfg.Kernel), Initrd: "sha256:" + digest(t, cfg.Initrd)}}
	lab.request(platform, "POST", "/v1/system-images", "base", image, 201, nil)
	limit := 4
	lab.request(platform, "PUT", "/v1/organizations/"+org.ID+"/quotas", "limit", controlplane.OrganizationQuotas{MaxAgents: &limit}, 200, nil)
	var tmpl controlplane.TemplateRevision
	lab.request(owner(), "POST", "/v1/templates", "template", controlplane.TemplateSpec{Name: "support", SystemImage: image.ID, Harness: controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}, 201, &tmpl)
	var bob controlplane.Member
	lab.request(owner(), "POST", "/v1/members", "bob", controlplane.CreateMemberInput{Issuer: identity.trust.Issuer, Subject: "bob", DisplayName: "Bob", Role: "agent_user"}, 201, &bob)
	var agents []string
	var lastDeployment string
	var activeAgent string
	var competing controlplane.Invocation
	var competingStart time.Time
	member := func() string { return identity.token(t, "bob") }
	t.Cleanup(func() {
		for _, id := range agents {
			cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := lab.worker.host.Retire(cleanup, id, ^uint64(0))
			cancel()
			if err != nil {
				t.Error(err)
			}
		}
		lab.worker.Close()
	})
	volumeDir := filepath.Join(lab.root, "volumes")
	for _, batch := range []int{1, 3} {
		ioStart := readDeploymentIO(volumeDir)
		start := time.Now()
		var plan controlplane.DeploymentPlan
		desired := 0
		if batch == 3 {
			desired = 1
		}
		lab.request(owner(), "POST", "/v1/deployment-plans", fmt.Sprintf("plan-%d", batch), controlplane.DeploymentRequest{Template: tmpl.Reference, Count: batch, ActiveCount: desired}, 201, &plan)
		if !plan.Admitted {
			details, _ := json.Marshal(plan.Checks)
			t.Fatalf("batch %d admission refusal: %s", batch, details)
		}
		lastDeployment = plan.ID
		apply := "/v1/deployment-plans/" + plan.ID + "/apply"
		applyStart := time.Now()
		lab.request(owner(), "POST", apply, "apply", struct{}{}, 202, nil)
		applyDuration := time.Since(applyStart)
		rows, err := lab.db.Query(ctx, "SELECT agent_id FROM agent_deployment_members WHERE deployment_id=$1 ORDER BY ordinal", plan.ID)
		if err != nil {
			t.Fatal(err)
		}
		var batchIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			batchIDs = append(batchIDs, id)
			agents = append(agents, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		if len(batchIDs) != batch {
			t.Fatal(batchIDs)
		}
		if batch == 3 {
			dispatch := DispatchOptions{Batch: 1, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
			lab.worker.afterWorkClaim = func(job controlplane.WorkerJob) {
				if job.Kind != "provision" || competing.ID != "" {
					return
				}
				if _, err := lab.worker.host.Control(ctx, activeAgent); err != nil {
					t.Fatal("expected existing active VM", err)
				}
				competingStart = time.Now()
				lab.request(member(), "POST", "/v1/agents/"+activeAgent+"/invocations", "during-provision", map[string]any{"content": []map[string]string{{"type": "text", "text": "serving during provisioning"}}}, 202, &competing)
			}
			if err := lab.worker.DispatchPass(ctx, dispatch, 90*time.Second); err != nil {
				t.Fatal(err)
			}
			lab.worker.afterWorkClaim = nil
			if competing.ID == "" {
				t.Fatal("no provision job observed")
			}
			var partly controlplane.DeploymentStatus
			lab.request(owner(), "GET", "/v1/deployments/"+plan.ID, "", nil, 200, &partly)
			if partly.Provisioned != 1 || partly.Pending != 2 {
				t.Fatal("before restart", partly)
			}
			old := lab.worker
			old.Close()
			options := opts(t, lab.root)
			options.AuthenticatedControl, options.Ready, options.BootTimeout = true, nil, time.Minute
			lab.worker, err = NewProvisioningPlacements(lab.store, old.hostID, "restarted-worker", 2*time.Minute, options, old.provisioning.keys, old.authority, old.provisioning.config)
			if err != nil {
				lab.worker = old
				t.Fatal(err)
			}
			if err = lab.worker.EnableTransit(ctx, old.transit.Load()); err != nil {
				t.Fatal(err)
			}
			lab.request(owner(), "POST", apply, "apply-after-interruption", struct{}{}, 202, nil)
		}
		if competing.ID != "" {
			lab.await("existing agent invocation during provisioning", true, func() bool {
				var inv controlplane.Invocation
				lab.request(member(), "GET", "/v1/invocations/"+competing.ID, "", nil, 200, &inv)
				return inv.State == "completed"
			})
			answer := lab.request(member(), "GET", "/v1/invocations/"+competing.ID+"/result", "", nil, 200, nil)
			if !strings.Contains(string(answer), "serving during provisioning") {
				t.Fatal("missing concurrent answer")
			}
			t.Logf("active_agent_invocation_during_provisioning=%s", time.Since(competingStart))
		}
		var result controlplane.DeploymentStatus
		lab.awaitFor("deployment completion", true, 5*time.Minute, func() bool {
			lab.request(owner(), "GET", "/v1/deployments/"+plan.ID, "", nil, 200, &result)
			return result.Status == "ready"
		})
		ioEnd := readDeploymentIO(volumeDir)
		logDeploymentIO(t, batch, ioStart, ioEnd)
		if result.Provisioned != batch || result.Active != desired || result.WaitingCapacity != 0 {
			t.Fatal(result)
		}
		var registry struct {
			Agents map[string]runtime.HostAgent `json:"agents"`
		}
		data, err := os.ReadFile(filepath.Join(lab.root, "registry.json"))
		if err != nil || json.Unmarshal(data, &registry) != nil {
			t.Fatal("registry", err)
		}
		var seen []os.FileInfo
		var allocated, logical int64
		for _, id := range agents {
			a := registry.Agents[id]
			f, err := os.Open(a.Volume)
			if err != nil {
				t.Fatal(err)
			}
			var magic [6]byte
			_, err = f.Read(magic[:])
			st, statErr := f.Stat()
			f.Close()
			if err != nil || statErr != nil || !bytes.Equal(magic[:], []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}) {
				t.Fatal("LUKS header", id, err, statErr)
			}
			for _, v := range seen {
				if os.SameFile(v, st) {
					t.Fatal("shared inode", id)
				}
			}
			seen = append(seen, st)
			allocated += st.Sys().(*syscall.Stat_t).Blocks * 512
			logical += st.Size()
		}
		t.Logf("batch=%d provisioned=%d active=%d apply=%s elapsed=%s inventory_logical_bytes=%d inventory_allocated_bytes=%d", batch, result.Provisioned, result.Active, applyDuration, time.Since(start), logical, allocated)
		if batch == 1 {
			activeAgent = batchIDs[0]
			lab.request(owner(), "POST", "/v1/agents/"+activeAgent+"/assignments", "competing-agent", controlplane.CreateAssignmentInput{PrincipalID: bob.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, 201, nil)
			var wake controlplane.AgentCreation
			lab.request(owner(), "POST", "/v1/agents/"+activeAgent+"/wake", "competing-wake", struct{}{}, 202, &wake)
			lab.awaitOperation(owner, wake.OperationID)
		}
		if desired > 0 {
			id := batchIDs[len(batchIDs)-1]
			lab.request(owner(), "POST", "/v1/agents/"+id+"/assignments", "assign", controlplane.CreateAssignmentInput{PrincipalID: bob.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, 201, nil)
			started := time.Now()
			_, answer := lab.ask(func() string { return identity.token(t, "bob") }, id, "ask", "deployment response")
			if !strings.Contains(answer, "deployment response") {
				t.Fatal("missing answer")
			}
			t.Logf("first_response=%s", time.Since(started))
		}
	}
	var refused controlplane.DeploymentPlan
	lab.request(owner(), "POST", "/v1/deployment-plans", "over", controlplane.DeploymentRequest{Template: tmpl.Reference, Count: 1}, 201, &refused)
	if refused.Admitted {
		t.Fatal(refused)
	}
	lab.request(owner(), "POST", "/v1/deployment-plans/"+refused.ID+"/apply", "over", struct{}{}, 409, nil)
	var total, vols int
	if err := lab.db.QueryRow(ctx, "SELECT count(*),count(DISTINCT volume_id) FROM store_enrollments").Scan(&total, &vols); err != nil || total != 4 || vols != 4 {
		t.Fatal(total, vols, err)
	}
	var sleep controlplane.AgentCreation
	lab.request(owner(), "POST", "/v1/agents/"+activeAgent+"/sleep", "done-measuring", struct{}{}, 202, &sleep)
	lab.awaitOperation(owner, sleep.OperationID)
	testProductWarmReplacement(t, lab, owner, lastDeployment)
	testProductRollout(t, lab, owner, lastDeployment, tmpl)
}

func testProductWarmReplacement(t *testing.T, lab *productPeerLab, owner func() string, dep string) {
	t.Helper()
	ctx := t.Context()
	active := func() (string, uint64) {
		t.Helper()
		var id string
		var gen uint64
		if err := lab.db.QueryRow(ctx, `SELECT agent_id,generation FROM agent_placements JOIN agent_deployment_members USING(agent_id)
			WHERE deployment_id=$1 AND state='RUNNING' AND NOT fence_only`, dep).Scan(&id, &gen); err != nil {
			t.Fatal(err)
		}
		return id, gen
	}
	ready := func() bool {
		var d controlplane.DeploymentStatus
		lab.request(owner(), "GET", "/v1/deployments/"+dep, "", nil, 200, &d)
		return d.Active == 1 && d.Status == "ready"
	}
	id, generation := active()
	// Remove the actual VMM without a lifecycle request. Reconcile notices
	// the exit as it does on worker startup. No client sends a wake.
	if err := lab.worker.host.Retire(ctx, id, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := lab.worker.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if ready() {
		t.Fatal("retired VMM counted as active")
	}
	lab.await("replace lost warm VM", true, ready)
	recovered, next := active()
	if recovered != id || next <= generation {
		t.Fatal("unexpected replacement generation", id, generation, recovered, next)
	}
	var sleep controlplane.AgentCreation
	lab.request(owner(), "POST", "/v1/agents/"+id+"/sleep", "sleep-warm-member", struct{}{}, 202, &sleep)
	lab.awaitOperation(owner, sleep.OperationID)
	lab.await("replace sleeping warm member", true, ready)
	replacement, _ := active()
	if replacement == id {
		t.Fatal("explicit sleep overridden")
	}
	t.Logf("warm_target=1 lost_generation=%d recovered_generation=%d sleeping_member_replaced=true", generation, next)
}

// Remove only the disposable worker's target image, then repair its cache.
// The first failed member pauses the campaign with the later VMs untouched.
func testProductRollout(t *testing.T, lab *productPeerLab, owner func() string, dep string, initial controlplane.TemplateRevision) {
	spec := initial.TemplateSpec
	spec.Resources.VCPUs = 2
	spec.Resources.MemoryMiB = 384
	var revision controlplane.TemplateRevision
	lab.request(owner(), "POST", "/v1/templates", "upgrade", spec, 201, &revision)
	var rollout controlplane.Rollout
	lab.request(owner(), "POST", "/v1/deployments/"+dep+"/rollouts", "upgrade", controlplane.RolloutInput{Template: revision.Reference, MaxUnavailable: 2}, 202, &rollout)
	cache := filepath.Join(lab.root, "bin", "kernel-"+digest(t, config(t).Kernel))
	if err := os.Rename(cache, cache+"-offline"); err != nil {
		t.Fatal(err)
	}
	st := func() controlplane.Rollout {
		var state controlplane.Rollout
		lab.request(owner(), "GET", "/v1/rollouts/"+rollout.ID, "", nil, 200, &state)
		return state
	}
	lab.await("canary pause", true, func() bool { return st().Status == "paused" })
	paused := st()
	if paused.Maintaining != 1 || paused.Updated != 0 || paused.Booted != 0 {
		t.Fatal(paused)
	}
	if err := os.Rename(cache+"-offline", cache); err != nil {
		t.Fatal(err)
	}
	lab.request(owner(), "POST", "/v1/rollouts/"+rollout.ID+"/resume", "resume", struct{}{}, 202, nil)
	lab.awaitFor("rollout completion", true, 5*time.Minute, func() bool { return st().Status == "completed" })
	done := st()
	if done.Booted != 3 || done.Updated != 3 || done.Maintaining != 0 {
		t.Fatal(done)
	}
	var vmID string
	if err := lab.db.QueryRow(t.Context(), `SELECT p.vm_id FROM agent_deployment_members m JOIN agent_placements p USING(agent_id)
		WHERE m.deployment_id=$1 AND p.state='RUNNING' AND NOT p.fence_only`, dep).Scan(&vmID); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile(filepath.Join(lab.root, "jails", "firecracker", vmID, "root", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Machine struct {
			CPUs   int `json:"vcpu_count"`
			Memory int `json:"mem_size_mib"`
		} `json:"machine-config"`
	}
	if err := json.Unmarshal(boot, &config); err != nil || config.Machine.CPUs != spec.Resources.VCPUs || config.Machine.Memory != spec.Resources.MemoryMiB {
		t.Fatal("running Firecracker machine", config.Machine, err)
	}
	t.Logf("canary=%s booted_revision=%s authenticated_boots=%d vcpus=%d memory_mib=%d", paused.Reason, done.Template, done.Booted, config.Machine.CPUs, config.Machine.Memory)
}
