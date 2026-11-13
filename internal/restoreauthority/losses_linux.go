//go:build linux && cgo

package restoreauthority

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"slices"
)

// Declared losses (D-03 option B, docs/adr/003-restore-rpo.md). A restored
// image may lack outcomes this authority recorded. Each one is declared lost for
// that image's incarnation before activation, never withdrawn, and its job may
// then run again once under the same ID. These records stay outside the restored
// domain with the rest of the catalogue (D-05).

// Inspection checks the CURRENT restored data of one store against the outcomes
// this authority recorded for it, each with its current digest. It must check
// real effects AND deduplication/results, not just IDs. It returns the IDs that
// the image lacks or holds with another result. It runs inside a catalogue
// transaction and must not re-enter this catalogue.
type Inspection func(recorded []Outcome) (missing []string, err error)

// Restoration is what the trusted restore coordinator supplies to activate one
// restored image.
type Restoration struct {
	Inspect Inspection
	// Repair copies missing outcomes from an available archive into the image.
	// It runs outside any catalogue transaction, so it may validate archives
	// here. It returns nil when it has done what it could, including nothing
	// because no available archive holds them. Any error aborts the activation
	// before a declaration. A nil Repair means that no archive is available.
	Repair func(missing []Outcome) error
	// Publish makes the store Ready. It must still enforce the physical and
	// phase preconditions, and must not re-enter this catalogue.
	Publish func() error
}

// Loss is a declared loss: the restored image Incarnation of Store lacked the
// recorded outcome ID. Rerun is set once that outcome's rerun is recorded for
// the same incarnation, with its digest.
type Loss struct {
	ID          string
	Store       string
	Incarnation uint64
	Rerun       bool
	RerunDigest [32]byte
}

// Status is outcomeStatus in restore_authority.qnt: what a caller may learn
// about one outcome, for the current incarnation of its store.
type Status string

const (
	StatusUnrecorded     Status = "unrecorded"      // no outcome recorded
	StatusConfirmed      Status = "confirmed"       // recorded, no loss declared for this incarnation
	StatusLost           Status = "lost"            // declared lost for this incarnation; the rerun is pending
	StatusRerunConfirmed Status = "rerun_confirmed" // the rerun is recorded
)

// Activate is the activation path of a restored image. It repairs from an
// available archive first. Then it declares each outcome still missing, in a
// transaction that commits before Publish runs: a published Ready never hides
// an undeclared loss. Last, WithActivation checks again and publishes. It
// returns the losses declared for this incarnation, even when Publish fails.
func (c *Catalog) Activate(ctx context.Context, r Receipt, a Restoration) ([]Loss, error) {
	if a.Inspect == nil || a.Publish == nil {
		return nil, ErrInput
	}
	if a.Repair != nil {
		var missing []Outcome
		err := c.transaction(ctx, func(tx *sql.Tx) error {
			var err error
			missing, err = c.missingOutcomes(ctx, tx, r, a.Inspect)
			return err
		})
		if err != nil {
			return nil, err
		}
		if len(missing) > 0 {
			if err = a.Repair(missing); err != nil {
				return nil, err
			}
		}
	}
	losses, err := c.declareLosses(ctx, r, a.Inspect)
	if err != nil {
		return nil, err
	}
	return losses, c.WithActivation(ctx, r, a.Inspect, a.Publish)
}

// declareLosses is declareLoss in the model. Only Activate calls it, after the
// repair: the model allows a declaration only when no archive can repair. It
// declares exactly what inspect reports missing, so never an outcome the image
// holds, and returns every loss declared for this incarnation. A retry
// therefore returns the same list, and nothing missing declares nothing.
func (c *Catalog) declareLosses(ctx context.Context, r Receipt, inspect Inspection) ([]Loss, error) {
	var losses []Loss
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if err := requireLosses(ctx, tx); err != nil {
			return err
		}
		missing, err := c.missingOutcomes(ctx, tx, r, inspect)
		if err != nil {
			return err
		}
		for _, o := range missing {
			if _, err = c.exec(ctx, tx, stmtLoss, o.ID, r.Store, r.Incarnation); err != nil {
				return err
			}
		}
		losses, err = queryLosses(ctx, tx, "l.store=? AND l.incarnation=?", r.Store, r.Incarnation)
		return err
	})
	return losses, err
}

// RecordRerun is recordRerun in the model. It follows the rerun's verified
// local commit and precedes its external success, like RecordOutcome, which
// calls it for a declared loss. It needs a loss declared for b's incarnation:
// one declared for an earlier incarnation does not allow a rerun now. A loss
// has at most one rerun: a retry with the same digest is a no-op, and another
// digest is ErrConflict.
func (c *Catalog) RecordRerun(ctx context.Context, b Binding, outcome Outcome) error {
	if !validName(outcome.ID) {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		if err := current(ctx, tx, b); err != nil {
			return err
		}
		if err := requireLosses(ctx, tx); err != nil {
			return err
		}
		return c.recordRerun(ctx, tx, b, outcome)
	})
}

func (c *Catalog) recordRerun(ctx context.Context, tx *sql.Tx, b Binding, outcome Outcome) error {
	var store string
	err := tx.QueryRowContext(ctx, "SELECT store FROM losses WHERE outcome=? AND incarnation=?", outcome.ID, b.Incarnation).Scan(&store)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotDeclared
	}
	if err != nil {
		return err
	}
	if store != b.Store {
		return ErrConflict
	}
	if _, err = c.exec(ctx, tx, stmtRerun, outcome.ID, b.Incarnation, outcome.Digest[:]); err != nil {
		return err
	}
	var digest []byte
	if err = tx.QueryRowContext(ctx, "SELECT digest FROM reruns WHERE outcome=? AND incarnation=?", outcome.ID, b.Incarnation).Scan(&digest); err != nil {
		return err
	}
	if !hmac.Equal(digest, outcome.Digest[:]) {
		return ErrConflict
	}
	return nil
}

// Losses lists every loss declared for a store, in every incarnation, with its
// rerun. A sealed store still lists them.
func (c *Catalog) Losses(ctx context.Context, store string) ([]Loss, error) {
	if !validName(store) {
		return nil, ErrInput
	}
	var losses []Loss
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if err := requireLosses(ctx, tx); err != nil {
			return err
		}
		_, _, err := binding(ctx, tx, store)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		if err != nil {
			return err
		}
		losses, err = queryLosses(ctx, tx, "l.store=?", store)
		return err
	})
	return losses, err
}

// OutcomeStatus is outcomeStatus in the model, for the incarnation that this
// authority holds as current for the outcome's store. It also returns every
// loss declared for the outcome. The model's due (the job must run again) also
// needs the outcome's subject, which only the caller knows: a lost job whose
// subject is revoked is not run again.
func (c *Catalog) OutcomeStatus(ctx context.Context, id string) (Status, []Loss, error) {
	if !validName(id) {
		return "", nil, ErrInput
	}
	status, losses := StatusUnrecorded, []Loss{}
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if err := requireLosses(ctx, tx); err != nil {
			return err
		}
		var incarnation uint64
		err := tx.QueryRowContext(ctx, "SELECT s.incarnation FROM outcomes o JOIN stores s ON s.id=o.store WHERE o.id=?", id).Scan(&incarnation)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if losses, err = queryLosses(ctx, tx, "l.outcome=?", id); err != nil {
			return err
		}
		status = StatusConfirmed
		for _, l := range losses {
			if l.Incarnation == incarnation {
				status = StatusLost
				if l.Rerun {
					status = StatusRerunConfirmed
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return status, losses, nil
}

// missingOutcomes runs the coordinator's inspection under a current fenced
// receipt. It refuses a reply that names an outcome this authority never
// recorded for the store: a declared loss always names acknowledged work.
func (c *Catalog) missingOutcomes(ctx context.Context, tx *sql.Tx, r Receipt, inspect Inspection) ([]Outcome, error) {
	if err := c.currentFences(ctx, tx, r); err != nil {
		return nil, err
	}
	withLosses, err := lossesAvailable(ctx, tx)
	if err != nil {
		return nil, err
	}
	recorded, err := recordedOutcomes(ctx, tx, withLosses, "o.store=?", r.Store)
	if err != nil {
		return nil, err
	}
	outcomes := make([]Outcome, len(recorded))
	for i, o := range recorded {
		outcomes[i] = o.Outcome
	}
	ids, err := inspect(slices.Clone(outcomes))
	if err != nil {
		return nil, err
	}
	lacks := make(map[string]bool, len(ids))
	for _, id := range ids {
		lacks[id] = true
	}
	missing := []Outcome{}
	for _, o := range outcomes {
		if lacks[o.ID] {
			missing = append(missing, o)
			delete(lacks, o.ID)
		}
	}
	if len(lacks) != 0 {
		return nil, ErrInput
	}
	return missing, nil
}

// accounted is the model's guard: each missing outcome is declared lost for
// this very incarnation. A loss declared for an earlier one does not count.
func accounted(ctx context.Context, tx *sql.Tx, missing []Outcome, incarnation uint64) error {
	if len(missing) == 0 {
		return nil
	}
	withLosses, err := lossesAvailable(ctx, tx)
	if err != nil {
		return err
	}
	if !withLosses {
		return ErrHistory
	}
	for _, o := range missing {
		lost, err := declared(ctx, tx, o.ID, incarnation)
		if err != nil {
			return err
		}
		if !lost {
			return ErrHistory
		}
	}
	return nil
}

func declared(ctx context.Context, tx *sql.Tx, id string, incarnation uint64) (bool, error) {
	var lost bool
	err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM losses WHERE outcome=? AND incarnation=?)", id, incarnation).Scan(&lost)
	return lost, err
}

type recordedOutcome struct {
	Outcome
	store string
}

// recordedOutcomes gives each outcome its current digest: its latest rerun's,
// or else the first one. where is a fixed fragment, never built from input.
func recordedOutcomes(ctx context.Context, tx *sql.Tx, withLosses bool, where string, arg string) ([]recordedOutcome, error) {
	digest := "o.digest"
	if withLosses {
		digest = "coalesce((SELECT r.digest FROM reruns r WHERE r.outcome=o.id ORDER BY r.incarnation DESC LIMIT 1),o.digest)"
	}
	rows, err := tx.QueryContext(ctx, "SELECT o.id,o.store,"+digest+" FROM outcomes o WHERE "+where+" ORDER BY o.id", arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	recorded := []recordedOutcome{}
	for rows.Next() {
		var o recordedOutcome
		var d []byte
		if err = rows.Scan(&o.ID, &o.store, &d); err != nil || len(d) != 32 {
			return nil, errors.Join(ErrUnavailable, err)
		}
		copy(o.Digest[:], d)
		recorded = append(recorded, o)
	}
	return recorded, rows.Err()
}

// where is a fixed fragment, never built from input.
func queryLosses(ctx context.Context, tx *sql.Tx, where string, args ...any) ([]Loss, error) {
	rows, err := tx.QueryContext(ctx, `SELECT l.outcome,l.store,l.incarnation,r.digest FROM losses l
 LEFT JOIN reruns r ON r.outcome=l.outcome AND r.incarnation=l.incarnation WHERE `+where+` ORDER BY l.incarnation,l.outcome`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	losses := []Loss{}
	for rows.Next() {
		var l Loss
		var digest []byte
		if err = rows.Scan(&l.ID, &l.Store, &l.Incarnation, &digest); err != nil {
			return nil, err
		}
		if digest != nil {
			if len(digest) != 32 {
				return nil, ErrUnavailable
			}
			l.Rerun = true
			copy(l.RerunDigest[:], digest)
		}
		losses = append(losses, l)
	}
	return losses, rows.Err()
}
