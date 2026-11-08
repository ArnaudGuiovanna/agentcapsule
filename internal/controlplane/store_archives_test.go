package controlplane

import (
	"errors"
	"testing"
	"time"
)

func TestArchivePlanRequiresCleanStoppedLiveStore(t *testing.T) {
	s, _, _, _, _, e := instructionLab(t)
	// Enrollment's local fixture retires forcibly. First establish the trusted
	// clean-stop observation explicitly; no VM execution is claimed by this test.
	if _, err := s.StoreArchiveTarget(t.Context(), e.AgentID, e.HostID); !errors.Is(err, ErrPlacement) {
		t.Fatal("forced enrollment stop authorized archive", err)
	}
	p, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "clean-observation", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, p.Generation, false); err != nil {
		t.Fatal(err)
	}
	plan, err := s.StoreArchiveTarget(t.Context(), e.AgentID, e.HostID)
	if err != nil || plan.Inode != 100 || plan.Device != 1 || plan.Enrollment.VolumeID != e.VolumeID {
		t.Fatal("clean stopped archive target", plan, err)
	}
	p, err = s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "writer", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.StoreArchiveTarget(t.Context(), e.AgentID, e.HostID); !errors.Is(err, ErrPlacement) {
		t.Fatal("active writer authorized archive", err)
	}
	if err = s.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, p.Generation, true); err != nil {
		t.Fatal(err)
	}
	if _, err = s.StoreArchiveTarget(t.Context(), e.AgentID, e.HostID); !errors.Is(err, ErrPlacement) {
		t.Fatal("unclean stop treated as coherent capture", err)
	}
}
