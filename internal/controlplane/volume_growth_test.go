package controlplane

import (
	"errors"
	"testing"
	"time"
)

func TestVolumeGrowthReservesCapacityAndFencesOrdinaryBoot(t *testing.T) {
	l, c, owner, rev := deploymentLab(t)
	ctx := t.Context()
	plan := testDeploymentPlan(t, c, owner, "plan", DeploymentRequest{Template: rev.Reference, Count: 1})
	if _, err := c.ApplyDeployment(ctx, owner, plan.ID, "apply"); err != nil {
		t.Fatal(err)
	}
	jobs, err := l.s.PendingProvisioning(ctx, c.host, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatal(jobs, err)
	}
	e := jobs[0]
	if err = l.s.RecordProvisionedVolume(ctx, ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, OperationID: e.OperationID, VolumeID: e.VolumeID, Device: 1, Inode: 1}); err != nil {
		t.Fatal(err)
	}
	retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
	if err = l.s.ActivateProvisionedAgent(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err = l.s.ConfigureHostStorage(ctx, c.host, 128); err != nil {
		t.Fatal(err)
	}
	if _, err = c.RequestGrowth(ctx, owner, e.AgentID, "too-big", GrowthInput{129}); !errors.Is(err, ErrStorageCapacity) {
		t.Fatal(err)
	}
	if _, err = c.RequestGrowth(ctx, owner, e.AgentID, "same", GrowthInput{64}); !errors.Is(err, ErrTransition) {
		t.Fatal(err)
	}
	if _, err = c.RequestGrowth(ctx, owner, e.AgentID, "grow", GrowthInput{128}); err != nil {
		t.Fatal(err)
	}
	next := testDeploymentPlan(t, c, owner, "competitor", DeploymentRequest{Template: rev.Reference, Count: 1})
	if next.Admitted {
		t.Fatal("another deployment used the growth reserve")
	}
	g, err := l.s.NextGrowth(ctx, c.host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.BeginVolumeRestore(ctx, newID("rst"), e.AgentID, c.host, newID("arc")); !errors.Is(err, ErrRestore) {
		t.Fatal(err)
	}
	if err = l.s.AdvanceGrowth(ctx, g, "capturing"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.ClaimPlacement(ctx, e.AgentID, c.host, "test", time.Minute); !errors.Is(err, ErrPlacementBusy) {
		t.Fatal(err)
	}
}
