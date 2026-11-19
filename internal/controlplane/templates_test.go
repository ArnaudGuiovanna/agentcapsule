package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func deploymentLab(t *testing.T) (*tenantLab, *AgentCatalog, Principal, TemplateRevision) {
	t.Helper()
	l, c, owner := agentLab(t)
	image := SystemImage{"ubuntu@1", ImageDigests{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("a", 64)}}
	if err := l.s.ReportDeploymentHost(t.Context(), c.host, HostProvisioningBudget{MaxActive: 8, VCPUs: 16, UIDSlots: 10000, MemoryMiB: 16384}, []ImageDigests{image.ImageDigests}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApproveSystemImage(t.Context(), l.platform, "approve", image); err != nil {
		t.Fatal(err)
	}
	spec := TemplateSpec{Name: "support", SystemImage: image.ID, Harness: HarnessReference{"reference", "1.0.0"}, Resources: AgentResources{1, 256, 64}, Capabilities: []string{}}
	r, err := c.PublishTemplate(t.Context(), owner, "publish", spec)
	var rev TemplateRevision
	if err != nil || json.Unmarshal(r.Body, &rev) != nil || rev.Reference != "support@1" {
		t.Fatal(err, string(r.Body))
	}
	return l, c, owner, rev
}
func testDeploymentPlan(t *testing.T, c *AgentCatalog, p Principal, key string, in DeploymentRequest) DeploymentPlan {
	t.Helper()
	r, err := c.PlanDeployment(t.Context(), p, key, in)
	var plan DeploymentPlan
	if err != nil || json.Unmarshal(r.Body, &plan) != nil {
		t.Fatal(err, string(r.Body))
	}
	return plan
}
func TestDeploymentResumesWithDistinctVolumesAndImmutableTemplate(t *testing.T) {
	l, c, owner, rev := deploymentLab(t)
	ctx := t.Context()
	plan := testDeploymentPlan(t, c, owner, "plan", DeploymentRequest{Template: rev.Reference, Count: 3, ActiveCount: 1})
	spec := rev.TemplateSpec
	spec.Resources.MemoryMiB = 1024
	if _, err := c.PublishTemplate(ctx, owner, "revision2", spec); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			_, err := c.ApplyDeployment(ctx, owner, plan.ID, fmt.Sprintf("race-%d", i))
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	jobs, err := l.s.PendingProvisioning(ctx, c.host, 10)
	if err != nil || len(jobs) != 3 {
		t.Fatal(jobs, err)
	}
	for i, e := range jobs {
		if e.Resources.MemoryMiB != 256 || e.SystemImage.Initrd == "" {
			t.Fatal("immutable revision", e)
		}
		cap, err := c.AgentCapabilities(ctx, owner, e.AgentID)
		if err != nil || len(cap.Effective) != 0 {
			t.Fatal("explicit empty capability policy", cap, err)
		}
		err = l.s.RecordProvisionedVolume(ctx, ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, OperationID: e.OperationID, VolumeID: e.VolumeID, Device: 1, Inode: uint64(101 + i)})
		if err != nil {
			t.Fatal(err)
		}
		retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
		if err = l.s.ActivateProvisionedAgent(ctx, e); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			// The API process and idempotency receipt can both disappear.
			if _, err = l.s.pool.Exec(ctx, "DELETE FROM tenant_http_receipts WHERE operation=$1", "deployment.apply/"+plan.ID); err != nil {
				t.Fatal(err)
			}
			c, err = NewAgentCatalog(l.a, "local")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.ApplyDeployment(ctx, owner, plan.ID, "after-restart"); err != nil {
				t.Fatal(err)
			}
			d, err := c.GetDeployment(ctx, owner, plan.ID)
			if err != nil || d.Provisioned != 1 || d.Pending != 2 {
				t.Fatal(d, err)
			}
		}
	}
	var agents, volumes, warm int
	err = l.s.pool.QueryRow(ctx, `SELECT count(DISTINCT e.agent_id),count(DISTINCT e.volume_id),count(*) FILTER(WHERE x.auto_start) FROM store_enrollments e JOIN agent_specs x USING(agent_id)`).Scan(&agents, &volumes, &warm)
	if err != nil || agents != 3 || volumes != 3 || warm != 1 {
		t.Fatal(agents, volumes, warm, err)
	}
	r, err := c.CreatePool(ctx, owner, "pool", PoolInput{"pool", plan.ID})
	var pool AgentPool
	if err != nil || json.Unmarshal(r.Body, &pool) != nil || pool.Available != 3 {
		t.Fatal(string(r.Body), err)
	}
	tx, err := l.s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = reservePoolAgents(ctx, tx, owner, pool.ID, 1); err != nil {
		t.Fatal(err)
	}
	if err = commit(ctx, tx); err != nil {
		t.Fatal(err)
	}
	pool, err = c.GetPool(ctx, owner, pool.ID)
	if err != nil || pool.Available != 3 || pool.Preparing != 1 {
		t.Fatal(pool, err)
	}
}
func TestDeploymentBatchSizesAndQuotaBoundaries(t *testing.T) {
	l, c, owner, rev := deploymentLab(t)
	ctx := t.Context()
	limit := 1151
	if _, err := l.a.SetOrganizationQuotas(ctx, l.platform, owner.TenantID, "quota", OrganizationQuotas{MaxAgents: &limit}); err != nil {
		t.Fatal(err)
	}
	if err := l.s.ConfigureHostStorage(ctx, c.host, int64(limit)*64); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 50, 100, 1000, 1} {
		key := newID("key")
		plan := testDeploymentPlan(t, c, owner, key, DeploymentRequest{Template: rev.Reference, Count: n})
		_, err := c.ApplyDeployment(ctx, owner, plan.ID, key)
		if !plan.Admitted {
			var short *DeploymentShortfall
			if !errors.As(err, &short) || short.Resource != "max_agents" || short.Required != 1 || *short.Available != 0 {
				t.Fatal("refusal", short, err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		var countAgents, countVolumes int
		err = l.s.pool.QueryRow(ctx, `SELECT count(DISTINCT e.agent_id),count(DISTINCT e.volume_id) FROM agent_deployment_members m JOIN store_enrollments e USING(agent_id) WHERE m.deployment_id=$1`, plan.ID).Scan(&countAgents, &countVolumes)
		want := n
		if !plan.Admitted {
			want = 0
		}
		if err != nil || countAgents != want || countVolumes != want {
			t.Fatal(n, countAgents, countVolumes, err)
		}
	}
	if got := count(t, l.s, "store_enrollments"); got != limit {
		t.Fatal("partial reservation", got)
	}
}
