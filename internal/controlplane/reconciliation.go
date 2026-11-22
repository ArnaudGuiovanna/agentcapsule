package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/reconciliation"
)

var ErrNotReconciled = reconciliation.ErrNotReconciled
var ErrReconciliationRecord = reconciliation.ErrReconciliationRecord
var ErrReconciliationConflict = reconciliation.ErrReconciliationConflict

type AuthorityRecord = reconciliation.AuthorityRecord
type AuthorityStore = reconciliation.AuthorityStore
type FailoverAnnouncement = reconciliation.FailoverAnnouncement
type ReconciliationAuthority = reconciliation.ReconciliationAuthority
type Reconciliation = reconciliation.Reconciliation
type ReconciledWindow = reconciliation.ReconciledWindow
type StoreDivergence = reconciliation.StoreDivergence

const DivergenceNotEnrolled = reconciliation.DivergenceNotEnrolled
const DivergenceNotRegistered = reconciliation.DivergenceNotRegistered
const DivergenceVolume = reconciliation.DivergenceVolume
const DivergenceIncarnation = reconciliation.DivergenceIncarnation
const DivergenceUnknownAgent = reconciliation.DivergenceUnknownAgent
const DivergencePhase = reconciliation.DivergencePhase

// reconciler is the account a resumed deletion names as its requester.
const reconciler = "authority-reconciliation"

func (s *Store) Reconciled(ctx context.Context, epoch uint64) (bool, error) {
	return reconciliation.Reconciled(ctx, s.pool, epoch)
}

// CheckReconciled fails with ErrNotReconciled until PostgreSQL has been
// reconciled with epoch.
func (s *Store) CheckReconciled(ctx context.Context, epoch uint64) error {
	ok, err := s.Reconciled(ctx, epoch)
	if err == nil && !ok {
		err = ErrNotReconciled
	}
	return err
}

// Reconcile replays the authority's records and resumes lost deletions with the store's transaction discipline.
func (s *Store) Reconcile(ctx context.Context, a ReconciliationAuthority) (Reconciliation, error) {
	return reconciliation.Reconcile(ctx, s.pool, a, s.replayRecord, s.resumeDeletion)
}

func (s *Store) replayRecord(ctx context.Context, r AuthorityRecord) (bool, error) {
	if !r.Valid() {
		return false, ErrReconciliationRecord
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	applied, err := reconciliation.ReplayRecord(ctx, tx, r)
	if err != nil || !applied {
		return false, err
	}
	return true, commit(ctx, tx)
}

func (s *Store) resumeDeletion(ctx context.Context, id string) (bool, string, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return false, "", err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, id)
	if err != nil {
		return false, "", err
	}
	a, ok := agents[id]
	if !ok {
		return false, DivergenceUnknownAgent, nil
	}
	var requested bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deletion_operations WHERE agent_id=$1)`, id).Scan(&requested); err != nil || requested {
		return false, "", err
	}
	if a.Phase != "LIVE" && a.Phase != "QUIESCING" {
		return false, DivergencePhase, nil
	}
	if err = requestDeletion(ctx, tx, a, reconciler); err != nil {
		return false, "", err
	}
	return true, "", commit(ctx, tx)
}
