package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func deploymentLab(t *testing.T) (*tenantLab, *AgentCatalog, Principal, TemplateRevision) {
	t.Helper()
	l, c, owner := agentLab(t)
	image := SystemImage{ID: "ubuntu@1", ImageDigests: ImageDigests{"sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("a", 64)}}
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
	const inventory = `SELECT coalesce(array_agg(ROW(m.ordinal,m.agent_id,e.volume_id,e.operation_id)::text ORDER BY m.ordinal), '{}'),
 count(DISTINCT m.agent_id), count(DISTINCT e.volume_id), count(DISTINCT e.operation_id)
 FROM agent_deployment_members m
 JOIN store_enrollments e USING (agent_id)
 JOIN platform_operations p ON p.id=e.operation_id AND p.agent_id=m.agent_id AND p.kind='provision'
 WHERE m.deployment_id=$1`
	snapshot := func(s *Store, planID string, want int) []string {
		t.Helper()
		var members []string
		var agents, volumes, operations int
		err := s.pool.QueryRow(ctx, inventory, planID).Scan(&members, &agents, &volumes, &operations)
		if err != nil || len(members) != want || agents != want || volumes != want || operations != want {
			t.Fatalf("batch inventory: want %d, members %d, agents %d, volumes %d, operations %d, error %v", want, len(members), agents, volumes, operations, err)
		}
		return members
	}

	// The fixture's original store participates in the first apply. Each
	// restart closes the active pool and constructs fresh API components.
	store := l.s
	dsn := store.pool.Config().ConnString()
	t.Cleanup(func() { store.Close() })
	startCounts := make(map[string]int)
	for _, table := range []string{"agents", "agent_specs", "platform_operations", "store_enrollments", "agent_deployment_members"} {
		startCounts[table] = count(t, store, table)
	}
	reserved := 0
	for _, n := range []int{1, 50, 100, 1000, 1} {
		key := newID("key")
		plan := testDeploymentPlan(t, c, owner, key, DeploymentRequest{Template: rev.Reference, Count: n})
		if plan.Admitted != (reserved+n <= limit) {
			t.Fatalf("unexpected admission for %d with %d remaining: %v", n, limit-reserved, plan.Admitted)
		}
		_, err := c.ApplyDeployment(ctx, owner, plan.ID, key)
		if !plan.Admitted {
			var short *DeploymentShortfall
			if !errors.As(err, &short) || short.Resource != "max_agents" || short.Required != 1 || short.Available == nil || *short.Available != 0 {
				t.Fatal("refusal", short, err)
			}
			snapshot(store, plan.ID, 0)
			t.Logf("refused requested=%d resource=%s available=%d", n, short.Resource, *short.Available)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		before := snapshot(store, plan.ID, n)
		deleted, err := store.pool.Exec(ctx, "DELETE FROM tenant_http_receipts WHERE operation=$1", "deployment.apply/"+plan.ID)
		if err != nil || deleted.RowsAffected() != 1 {
			t.Fatalf("expected one expired apply receipt: %d, %v", deleted.RowsAffected(), err)
		}
		store.Close()
		reopened, err := Open(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		store = reopened
		accounts, err := NewAccounts(store, bytes.Repeat([]byte{0x42}, 32)) // same fixture key as accountLab
		if err != nil {
			t.Fatal(err)
		}
		c, err = NewAgentCatalog(accounts, c.host)
		if err != nil {
			t.Fatal(err)
		}
		replayed, err := c.ApplyDeployment(ctx, owner, plan.ID, newID("key"))
		if err != nil || replayed.Status != 202 {
			t.Fatalf("reapply after restart: status %d, error %v", replayed.Status, err)
		}
		if !slices.Equal(before, snapshot(store, plan.ID, n)) {
			t.Fatal("reapplying changed the ordinal, agent, volume or provisioning operation")
		}
		reserved += n
		t.Logf("reopened and reapplied requested=%d unchanged_members=%d cumulative=%d", n, len(before), reserved)
	}
	for table, initial := range startCounts {
		if got := count(t, store, table) - initial; got != limit {
			t.Fatalf("partial or duplicate reservation: %s grew by %d, want %d", table, got, limit)
		}
	}
}

func TestDeploymentMaintainsWarmTargetWithoutEvicting(t *testing.T) {
	l, c, owner, rev := deploymentLab(t)
	ctx := t.Context()
	plan := testDeploymentPlan(t, c, owner, "plan", DeploymentRequest{Template: rev.Reference, Count: 2, ActiveCount: 1})
	if _, err := c.ApplyDeployment(ctx, owner, plan.ID, "apply"); err != nil {
		t.Fatal(err)
	}
	cold := testDeploymentPlan(t, c, owner, "cold", DeploymentRequest{Template: rev.Reference, Count: 1})
	if _, err := c.ApplyDeployment(ctx, owner, cold.ID, "cold"); err != nil {
		t.Fatal(err)
	}
	var neighbor string
	if err := l.s.pool.QueryRow(ctx, "SELECT agent_id FROM agent_deployment_members WHERE deployment_id=$1", cold.ID).Scan(&neighbor); err != nil {
		t.Fatal(err)
	}
	enrollments, err := l.s.PendingProvisioning(ctx, c.host, 10)
	if err != nil || len(enrollments) != 3 {
		t.Fatal(enrollments, err)
	}
	var preferred string
	for i, e := range enrollments {
		if e.AutoStart {
			preferred = e.AgentID
		}
		if err := l.s.RecordProvisionedVolume(ctx, ProvisionedVolume{AgentID: e.AgentID, HostID: c.host, OperationID: e.OperationID, VolumeID: e.VolumeID, Device: 1, Inode: uint64(i + 100)}); err != nil {
			t.Fatal(err)
		}
		retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
		if err := l.s.ActivateProvisionedAgent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	hostLimit := func(slots int) {
		t.Helper()
		if _, err := l.s.pool.Exec(ctx, "UPDATE deployment_hosts SET max_active=$2 WHERE host_id=$1", c.host, slots); err != nil {
			t.Fatal(err)
		}
	}
	hostLimit(1)
	second := testDeploymentPlan(t, c, owner, "second", DeploymentRequest{Template: rev.Reference, Count: 1, ActiveCount: 1})
	if second.Admitted {
		t.Fatal("new deployment took a warm reservation between boots")
	}
	claim := func(id string) error {
		_, err := l.s.ClaimWarmPlacement(ctx, id, c.host, "worker", time.Minute)
		return err
	}
	pick := func() string {
		t.Helper()
		id, err := l.s.NextWarmAgent(ctx, c.host)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	none := func() {
		t.Helper()
		if id, err := l.s.NextWarmAgent(ctx, c.host); !errors.Is(err, ErrNoWork) {
			t.Fatal("unexpected warm candidate", id, err)
		}
	}
	if got := pick(); got != preferred {
		t.Fatal(got, preferred)
	}
	// A user sleep after selection invalidates the hint and an alternate
	// member can satisfy the same target.
	if _, err := c.RequestLifecycle(ctx, owner, preferred, "manual-sleep", "sleep"); err != nil {
		t.Fatal(err)
	}
	if err := claim(preferred); !errors.Is(err, ErrNoWork) {
		t.Fatal("stale hint after sleep", err)
	}
	id := pick()
	if id == preferred {
		t.Fatal("selected sleeping agent")
	}
	near, err := l.s.ClaimPlacement(ctx, neighbor, c.host, "neighbor", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	none()
	if err := claim(id); !errors.Is(err, ErrNoWork) {
		t.Fatal("warm claim with full host", err)
	}
	hostLimit(2)
	lim := 1
	if _, err := l.a.SetOrganizationQuotas(ctx, l.platform, owner.TenantID, "quota", OrganizationQuotas{MaxActiveVMs: &lim}); err != nil {
		t.Fatal(err)
	}
	none()
	if _, err := l.a.SetOrganizationQuotas(ctx, l.platform, owner.TenantID, "clear", OrganizationQuotas{}); err != nil {
		t.Fatal(err)
	}
	if got := pick(); got != id {
		t.Fatal(got, id)
	}
	if err := l.s.ObservePlacementStopped(ctx, neighbor, c.host, near.Generation, false); err != nil {
		t.Fatal(err)
	}
	hostLimit(1)
	// Other work taking the last slot after selection prevents a warm boot.
	// Its ordinary boot also satisfies the deployment even with a second slot free.
	other, err := l.s.ClaimPlacement(ctx, preferred, c.host, "work", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim(id); !errors.Is(err, ErrNoWork) {
		t.Fatal("warm claim with occupied host", err)
	}
	hostLimit(2)
	none()
	if err := l.s.ObservePlacementStopped(ctx, preferred, c.host, other.Generation, false); err != nil {
		t.Fatal(err)
	}
	if got := pick(); got != id {
		t.Fatal(got, id)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- claim(id) })
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrNoWork) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("generation claims", successes)
	}
	none()
}
