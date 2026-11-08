package controlplane

import (
	"errors"
	"testing"
	"time"
)

func TestProvisioningQueueResumesWithoutBlockingLaterReservations(t *testing.T) {
	s, accounts, catalog, admin, _, owner := catalogLab(t)
	first := reserveEnrollment(t, s, catalog, owner, false)
	other := createAccount(t, accounts, admin, "second-owner", "Other")
	if _, err := catalog.Reserve(t.Context(), admin, "second-agent", catalogInput(other.ID)); err != nil {
		t.Fatal(err)
	}
	if err := s.DiscoverWork(t.Context(), "local", 1); err != nil {
		t.Fatal(err)
	}
	one, err := s.ClaimWork(t.Context(), "local", time.Minute)
	if err != nil || one.Kind != "provision" || one.ID != first.OperationID || one.AgentID != first.AgentID {
		t.Fatal(one, err)
	}
	if _, err = s.ProvisioningTarget(t.Context(), one.AgentID, "foreign", one.ID); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("foreign host accepted", err)
	}
	if _, err = s.ProvisioningTarget(t.Context(), one.AgentID, "local", "wrong-operation"); !errors.Is(err, ErrStoreEnrollment) {
		t.Fatal("foreign operation accepted", err)
	}
	if err = s.RetryWork(t.Context(), one, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Migration preserves the pending ticket; discovery excludes existing jobs
	// before applying its limit, so the failing oldest reservation cannot starve it.
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.DiscoverWork(t.Context(), "local", 1); err != nil {
			t.Fatal(err)
		}
	}
	two, err := s.ClaimWork(t.Context(), "local", time.Minute)
	if err != nil || two.Kind != "provision" || two.ID == one.ID {
		t.Fatal("later reservation starved", two, err)
	}
	if count(t, s, "worker_jobs") != 2 {
		t.Fatal("duplicate discovery or dropped retry")
	}
	observeTestVolume(t, s, first)
	retireEnrollmentBoot(t, s, enrollmentBoot(t, s, first))
	if err = s.ActivateProvisionedAgent(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	current, err := s.ProvisioningTarget(t.Context(), first.AgentID, first.HostID, first.OperationID)
	if err != nil || current.Stage != "READY" {
		t.Fatal("lost activation ACK not replayable", current, err)
	}
	if err = s.RequestDeletion(t.Context(), owner.ID, first.AgentID); err != nil {
		t.Fatal(err)
	}
	current, err = s.ProvisioningTarget(t.Context(), first.AgentID, first.HostID, first.OperationID)
	if err != nil || current.Stage != "READY" {
		t.Fatal("completed provisioning replay tried to resurrect agent", current, err)
	}
}
