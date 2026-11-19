package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRolloutCanaryRebootMaintenanceAndWaves(t *testing.T) {
	l, c, owner, rev := deploymentLab(t)
	ctx := t.Context()
	plan := testDeploymentPlan(t, c, owner, "plan", DeploymentRequest{Template: rev.Reference, Count: 4})
	if _, err := c.ApplyDeployment(ctx, owner, plan.ID, "apply"); err != nil {
		t.Fatal(err)
	}
	enrollments, err := l.s.PendingProvisioning(ctx, c.host, 10)
	if err != nil || len(enrollments) != 4 {
		t.Fatal(len(enrollments), err)
	}
	for i, e := range enrollments {
		if err := l.s.RecordProvisionedVolume(ctx, ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, OperationID: e.OperationID, VolumeID: e.VolumeID, Device: 1, Inode: uint64(100 + i)}); err != nil {
			t.Fatal(err)
		}
		retireEnrollmentBoot(t, l.s, enrollmentBoot(t, l.s, e))
		if err := l.s.ActivateProvisionedAgent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	spec := rev.TemplateSpec
	spec.Resources.VCPUs = 2
	spec.Resources.MemoryMiB = 512
	if _, err := c.PublishTemplate(ctx, owner, "next", spec); err != nil {
		t.Fatal(err)
	}
	r, err := c.StartRollout(ctx, owner, plan.ID, "roll", RolloutInput{"support@2", 2})
	var roll Rollout
	if err != nil || json.Unmarshal(r.Body, &roll) != nil || roll.Total != 4 {
		t.Fatal(string(r.Body), err)
	}
	for i := range 4 {
		id, a, err := l.s.NextRollout(ctx, c.host)
		if err != nil || id != roll.ID {
			t.Fatal(id, a, err)
		}
		st, err := l.s.RolloutStep(ctx, id, a, c.host, false)
		if err != nil || st.Stage != "draining" {
			t.Fatal(st, err)
		}
		if _, err = l.s.ClaimPlacement(ctx, a, c.host, "outside", time.Minute); !errors.Is(err, ErrPlacementBusy) {
			t.Fatal("unexpected wake during maintenance", err)
		}
		if i == 0 {
			if err = l.s.PauseRollout(ctx, id, a, "artifact_unavailable"); err != nil {
				t.Fatal(err)
			}
			if _, _, err = l.s.NextRollout(ctx, c.host); !errors.Is(err, ErrNoWork) {
				t.Fatal("second agent touched before canary", err)
			}
			state, err := c.GetRollout(ctx, owner, id)
			if err != nil || state.Status != "paused" || state.Maintaining != 1 || state.Booted != 0 {
				t.Fatal(state, err)
			}
			if _, err := c.ResumeRollout(ctx, owner, id, "resume"); err != nil {
				t.Fatal(err)
			}
		}
		if err = l.s.InstallRolloutSpec(ctx, st); err != nil {
			t.Fatal(err)
		}
		p, err := l.s.ClaimRolloutPlacement(ctx, a, c.host, "worker", id, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		p.VMID = fmt.Sprintf("%016x", p.Generation)
		if err = l.s.ConfirmPlacement(ctx, a, c.host, "worker", p.Generation, p.VMID); err != nil {
			t.Fatal(err)
		}
		if err = l.s.ObserveRolloutBoot(ctx, st, p.Generation, p.VMID); !errors.Is(err, ErrPlacement) {
			t.Fatal("unverified boot counted", err)
		}
		if err = l.s.ObservePlacementControl(ctx, PlacementControlObservation{AgentID: a, HostID: c.host, VMID: p.VMID, Generation: p.Generation, Incarnation: 1, Compatible: true}); err != nil {
			t.Fatal(err)
		}
		if err = l.s.ObserveRolloutBoot(ctx, st, p.Generation, p.VMID); err != nil {
			t.Fatal(err)
		}
		retireEnrollmentBoot(t, l.s, p)
		if err = l.s.FinishRolloutStep(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	end, err := c.GetRollout(ctx, owner, roll.ID)
	if err != nil || end.Status != "completed" || end.Maintaining != 0 || end.Booted != 4 || end.Updated != 4 {
		t.Fatal(end, err)
	}
	for _, orig := range enrollments {
		e, err := l.s.VolumeEnrollment(ctx, orig.AgentID, c.host)
		if err != nil || e.VolumeID != orig.VolumeID || e.Resources != spec.Resources {
			t.Fatal(e, err)
		}
	}
}
