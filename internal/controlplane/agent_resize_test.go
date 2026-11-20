package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func requestTestResize(t *testing.T, c *AgentCatalog, owner Principal, agent string, target ComputeResources) Rollout {
	t.Helper()
	ctx := t.Context()
	first, err := c.ResizeAgent(ctx, owner, agent, "resize", target)
	var result Rollout
	if err != nil || json.Unmarshal(first.Body, &result) != nil || first.Status != 202 || result.AgentID != agent ||
		result.Total != 1 || result.Resources == nil || *result.Resources != target || result.Template != "" || result.DeploymentID != "" {
		t.Fatal(result, err)
	}
	again, err := c.ResizeAgent(ctx, owner, agent, "resize", target)
	if err != nil || !again.Replayed || string(again.Body) != string(first.Body) {
		t.Fatal("replay", err)
	}
	if _, err = c.ResizeAgent(ctx, owner, agent, "duplicate", target); !errors.Is(err, ErrTransition) {
		t.Fatal("second resize admitted", err)
	}
	if _, err = c.RequestGrowth(ctx, owner, agent, "overlap-growth", GrowthInput{256}); !errors.Is(err, ErrTransition) {
		t.Fatal("growth admitted", err)
	}
	return result
}

func confirmResizePlacement(t *testing.T, s *Store, p Placement) Placement {
	t.Helper()
	ctx := t.Context()
	p.VMID = fmt.Sprintf("%016x", p.Generation)
	if err := s.ConfirmPlacement(ctx, p.AgentID, p.HostID, p.WorkerID, p.Generation, p.VMID); err != nil {
		t.Fatal(err)
	}
	return p
}

func checkResizeBoot(t *testing.T, s *Store, st RolloutStep, p Placement) {
	t.Helper()
	ctx := t.Context()
	p = confirmResizePlacement(t, s, p)
	if err := s.ObserveRolloutBoot(ctx, st, p.Generation, p.VMID); !errors.Is(err, ErrPlacement) {
		t.Fatal("unverified boot counted", err)
	}
	if err := s.ObservePlacementControl(ctx, PlacementControlObservation{AgentID: p.AgentID, HostID: p.HostID, Generation: p.Generation, VMID: p.VMID, Incarnation: 1, Compatible: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.ObserveRolloutBoot(ctx, st, p.Generation, p.VMID); err != nil {
		t.Fatal(err)
	}
	if !st.KeepRunning {
		retireEnrollmentBoot(t, s, p)
	}
	if err := s.FinishRolloutStep(ctx, st); err != nil {
		t.Fatal(err)
	}
}

func TestResizeStandaloneRetainsEnrollmentAndPolicy(t *testing.T) {
	l, c, owner, _ := deploymentLab(t)
	ctx := t.Context()
	id := activateTenantAgent(t, l, c, owner, "standalone")
	before, err := l.s.VolumeEnrollment(ctx, id, c.host)
	if err != nil || before.SystemImage.Kernel != "" {
		t.Fatal(before, err)
	}
	if _, err = l.s.pool.Exec(ctx, "INSERT INTO agent_capability_policies(agent_id,allowed,updated_by) VALUES($1,'{}',$2)", id, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResizeAgent(ctx, owner, id, "bad", ComputeResources{9, 512}); !errors.Is(err, ErrInput) {
		t.Fatal(err)
	}
	if _, err := c.ResizeAgent(ctx, owner, id, "no-change", ComputeResources{before.Resources.VCPUs, before.Resources.MemoryMiB}); !errors.Is(err, ErrTransition) {
		t.Fatal(err)
	}
	quota := 1
	if _, err = l.a.SetOrganizationQuotas(ctx, l.platform, owner.TenantID, "small", OrganizationQuotas{MaxVCPUs: &quota}); err != nil {
		t.Fatal(err)
	}
	target := ComputeResources{2, 512}
	var short *DeploymentShortfall
	if _, err := c.ResizeAgent(ctx, owner, id, "quota", target); !errors.As(err, &short) || short.Resource != "agent_vcpus" {
		t.Fatal("individually impossible target admitted", err)
	}
	if _, err = l.a.SetOrganizationQuotas(ctx, l.platform, owner.TenantID, "normal", OrganizationQuotas{}); err != nil {
		t.Fatal(err)
	}
	u := requestTestResize(t, c, owner, id, target)
	roll, agent, err := l.s.NextRollout(ctx, c.host)
	if err != nil || roll != u.ID || agent != id {
		t.Fatal(roll, agent, err)
	}
	st, err := l.s.RolloutStep(ctx, u.ID, id, c.host, false)
	if err != nil || !st.Resize || st.KeepRunning || st.Stage != "draining" || st.Target.SystemImage != before.SystemImage {
		t.Fatal(st, err)
	}
	if err = l.s.InstallRolloutSpec(ctx, st); err != nil {
		t.Fatal(err)
	}
	p, err := l.s.ClaimRolloutPlacement(ctx, id, c.host, "worker", u.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	checkResizeBoot(t, l.s, st, p)
	after, err := l.s.VolumeEnrollment(ctx, id, c.host)
	before.Resources.VCPUs, before.Resources.MemoryMiB = 2, 512
	if err != nil || after != before {
		t.Fatal("other enrollment fields changed", before, after, err)
	}
	var member, policy bool
	if err = l.s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT FROM agent_deployment_members WHERE agent_id=$1),
 EXISTS(SELECT FROM agent_capability_policies WHERE agent_id=$1 AND allowed='{}')`, id).Scan(&member, &policy); err != nil || member || !policy {
		t.Fatal(member, policy, err)
	}
	members, err := c.RolloutMembers(ctx, owner, u.ID, "", 10)
	if err != nil || len(members) != 1 || members[0].Requested != "" || members[0].LastVerified != "" || members[0].Resources == nil || *members[0].Resources != target || members[0].Generation == nil {
		t.Fatal(members, err)
	}
}

func TestResizeWarmMemberWaitsForAggregateQuota(t *testing.T) {
	l, c, owner, rev := deploymentLab(t)
	ctx := t.Context()
	dep := testDeploymentPlan(t, c, owner, "dep", DeploymentRequest{Template: rev.Reference, Count: 2, ActiveCount: 2})
	if _, err := c.ApplyDeployment(ctx, owner, dep.ID, "apply"); err != nil {
		t.Fatal(err)
	}
	entries, err := l.s.PendingProvisioning(ctx, c.host, 10)
	if err != nil || len(entries) != 2 {
		t.Fatal(entries, err)
	}
	var placements []Placement
	for i, e := range entries {
		if err = l.s.RecordProvisionedVolume(ctx, ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, OperationID: e.OperationID, VolumeID: e.VolumeID, Device: 1, Inode: uint64(100 + i)}); err != nil {
			t.Fatal(err)
		}
		retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
		if err = l.s.ActivateProvisionedAgent(ctx, e); err != nil {
			t.Fatal(err)
		}
		p, err := l.s.ClaimPlacement(ctx, e.AgentID, c.host, "worker", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		placements = append(placements, confirmResizePlacement(t, l.s, p))
	}
	limit := 3
	if _, err = l.a.SetOrganizationQuotas(ctx, l.platform, owner.TenantID, "quota", OrganizationQuotas{MaxVCPUs: &limit}); err != nil {
		t.Fatal(err)
	}
	id := entries[0].AgentID
	u := requestTestResize(t, c, owner, id, ComputeResources{3, 512})
	if _, err = c.StartRollout(ctx, owner, dep.ID, "overlap", RolloutInput{rev.Reference, 1}); !errors.Is(err, ErrTransition) {
		t.Fatal("overlapping deployment rollout", err)
	}
	next := testDeploymentPlan(t, c, owner, "new-warm", DeploymentRequest{Template: rev.Reference, Count: 1, ActiveCount: 1})
	if next.Admitted {
		t.Fatal("another deployment spent the pending warm resize reservation")
	}
	st, err := l.s.RolloutStep(ctx, u.ID, id, c.host, true)
	if err != nil || !st.KeepRunning || !st.Resize || st.Target.SystemImage != entries[0].SystemImage {
		t.Fatal(st, err)
	}
	if err = l.s.InstallRolloutSpec(ctx, st); !errors.Is(err, ErrPlacementBusy) {
		t.Fatal("installed on running VM", err)
	}
	retireEnrollmentBoot(t, l.s, placements[0])
	if err = l.s.InstallRolloutSpec(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.ClaimRolloutPlacement(ctx, id, c.host, "worker", u.ID, time.Minute); !errors.Is(err, ErrOrganizationQuota) {
		t.Fatal("boot exceeded the two members' aggregate quota", err)
	}
	if err = l.s.WaitRolloutCapacity(ctx, st); err != nil {
		t.Fatal(err)
	}
	waiting, err := c.GetRollout(ctx, owner, u.ID)
	if err != nil || waiting.Reason != "waiting_capacity" || waiting.Maintaining != 1 || waiting.Booted != 0 {
		t.Fatal(waiting, err)
	}
	peer, err := l.s.VolumeEnrollment(ctx, entries[1].AgentID, c.host)
	if err != nil || peer.Resources != entries[1].Resources || peer.VolumeID != entries[1].VolumeID {
		t.Fatal("peer modified", peer, err)
	}
	// Only an external release of the peer's capacity lets validation proceed.
	retireEnrollmentBoot(t, l.s, placements[1])
	p, err := l.s.ClaimRolloutPlacement(ctx, id, c.host, "worker", u.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	checkResizeBoot(t, l.s, st, p)
	end, err := c.GetRollout(ctx, owner, u.ID)
	if err != nil || end.Status != "completed" || end.Updated != 1 || end.Booted != 1 || end.Reason != "" {
		t.Fatal(end, err)
	}
	var n int
	if err = l.s.pool.QueryRow(ctx, "SELECT count(*) FROM agent_deployment_members m JOIN agent_deployments d ON d.id=m.deployment_id WHERE d.id=$1 AND d.template_name=$2 AND d.revision=$3 AND m.agent_id IN ($4,$5)", dep.ID, rev.Name, rev.Revision, id, entries[1].AgentID).Scan(&n); err != nil || n != 2 {
		t.Fatal("membership changed", n, err)
	}
}

func TestResizeWaitsForWorkingInvocationWithoutBlockingNeighbour(t *testing.T) {
	l := newInvocationLab(t)
	ctx := t.Context()
	image := ImageDigests{Kernel: "sha256:" + strings.Repeat("b", 64), Initrd: "sha256:" + strings.Repeat("a", 64)}
	if err := l.s.ReportDeploymentHost(ctx, l.c.host, HostProvisioningBudget{MaxActive: 4, VCPUs: 8, MemoryMiB: 8192, UIDSlots: 100}, []ImageDigests{image}); err != nil {
		t.Fatal(err)
	}
	vm := l.vm(t)
	invocation, _, err := l.create(t, l.invoker(t, "member"), "working", "summarize")
	if err != nil {
		t.Fatal(err)
	}
	l.ackWorking(t, invocation.ID)
	u := requestTestResize(t, l.c, l.owner, l.agent, ComputeResources{2, 512})
	neighbour := activateTenantAgent(t, l.tenantLab, l.c, l.owner, "neighbour")
	other := requestTestResize(t, l.c, l.owner, neighbour, ComputeResources{2, 512})
	first, _, err := l.s.NextRollout(ctx, l.c.host)
	if err != nil || first != u.ID {
		t.Fatal(first, err)
	}
	if _, err = l.s.RolloutStep(ctx, u.ID, l.agent, l.c.host, true); !errors.Is(err, ErrNoWork) {
		t.Fatal("drained agent while it was processing its invocation", err)
	}
	second, _, err := l.s.NextRollout(ctx, l.c.host)
	if err != nil || second != other.ID {
		t.Fatal("the running invocation blocked the independent resize", second, err)
	}
	if _, err = l.tr.CompleteInvocationFromVM(ctx, vm, "done", answer(invocation.ID, "ready")); err != nil {
		t.Fatal(err)
	}
	step, err := l.s.RolloutStep(ctx, u.ID, l.agent, l.c.host, true)
	if err != nil || step.Stage != "draining" || !step.KeepRunning {
		t.Fatal(step, err)
	}
}
