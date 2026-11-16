package api

import (
	"context"
	"sync/atomic"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// AuthorityEpoch gives the authority service's mode and epoch. It fails when
// the service does not answer with the identities the API pins.
type AuthorityEpoch func(context.Context) (mode string, epoch uint64, err error)

// ReconciledAuthority is the readiness probe's view of the authority
// service after ADR 006 wave 7: its mode, once PostgreSQL has been
// reconciled with the service's epoch (REPLAY_FIRST,
// docs/adr/005-keys-outside-restored-domain.md, item 15). Until then it
// fails with controlplane.ErrNotReconciled, and the probe answers 503
// authority_not_reconciled. An epoch found reconciled stays so: a
// reconciliation is never withdrawn, so the database is asked once per epoch.
func ReconciledAuthority(store *controlplane.Store, status AuthorityEpoch) AuthorityStatus {
	var reconciled atomic.Uint64
	return func(ctx context.Context) (string, error) {
		mode, epoch, err := status(ctx)
		if err != nil {
			return "", err
		}
		if epoch != reconciled.Load() {
			if err = store.CheckReconciled(ctx, epoch); err != nil {
				return "", err
			}
			reconciled.Store(epoch)
		}
		return mode, nil
	}
}
