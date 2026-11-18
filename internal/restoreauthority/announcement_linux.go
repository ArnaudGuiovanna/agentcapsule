//go:build linux && cgo

package restoreauthority

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
)

// The announcement after a failover (docs/adr/005-keys-outside-restored-domain.md,
// "What the code must do", item 14; docs/adr/006-authority-service.md §7,
// wave 7).
//
// The standby cannot know whether its primary ran in degraded mode before
// the disaster: by definition, it did not hear from it. It knows its last
// contact (contact_linux.go), and that no degraded period began less than the
// degraded delay after it. So the promotion compares the last contact with
// the failover, its own time:
//
//   - within the delay, no degraded period ran: every write the primary
//     confirmed is on the replica, and nothing more is announced than the
//     database's window (docs/recovery.md);
//   - beyond it, one may have. The promotion then writes into the promoted
//     catalogue one access revocation record, the blanket
//     (authoritylog.AccessBlanket): every bearer token issued before the
//     failover is revoked, every delegation trust's minimum_iat moves to the
//     failover, and the window from the last contact to the failover is
//     announced. Outcomes confirmed in it may be lost, and the revocations
//     still pending in it must be made again. The reconciliation replays the
//     record into PostgreSQL, as any other.
//
// A replica that never answered its primary has no last contact: that
// primary never reached it at this epoch, never entered degraded mode, and
// confirmed nothing the replica lacks.
//
// The decision is written in the replica, with its promotion mark, in one
// transaction: a repeated promotion announces the same.

// PromoteOptions tune a promotion.
type PromoteOptions struct {
	// DegradedAfter is the old primary's degraded delay, its
	// authority_replica.degraded_after: authoritylog.DefaultDegradedAfter
	// when zero, else within its bounds.
	DegradedAfter time.Duration
	// Now is the failover's clock; time.Now when nil. Tests replace it.
	Now func() time.Time
}

func (o PromoteOptions) withDefaults() (PromoteOptions, bool) {
	if o.DegradedAfter == 0 {
		o.DegradedAfter = authoritylog.DefaultDegradedAfter
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o, o.DegradedAfter >= authoritylog.MinDegradedAfter && o.DegradedAfter <= authoritylog.MaxDegradedAfter
}

// Announcement is what a failover announces.
type Announcement struct {
	// Epoch is the promoted authority's.
	Epoch uint64 `json:"epoch"`
	// Failover is when the promotion decided; zero when unknown (a promotion
	// by a release before wave 7, or a catalogue that only knows the blanket
	// record, without one).
	Failover time.Time `json:"failover,omitzero"`
	// LastContact is the standby's last contact with the old primary; zero
	// when it had none.
	LastContact time.Time `json:"last_contact,omitzero"`
	// DegradedAfter is the delay the promotion compared with; zero when
	// unknown.
	DegradedAfter time.Duration `json:"degraded_after_ns,omitempty"`
	// Degraded: a degraded period may have run. The window from LastContact
	// to Failover is announced, and Blanket is the ID of the record that
	// revokes every bearer token issued before Failover.
	Degraded bool   `json:"degraded"`
	Blanket  string `json:"blanket,omitempty"`
}

// promotionSchema is the replica's record of its promotion's decision. Like
// replica_contact, it is not part of the snapshot's schema.
const promotionSchema = `CREATE TABLE IF NOT EXISTS replica_promotion (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 epoch INTEGER NOT NULL CHECK(epoch>1),
 failover_at INTEGER NOT NULL CHECK(failover_at>0),
 contact_at INTEGER CHECK(contact_at IS NULL OR contact_at>0),
 degraded_after_ms INTEGER NOT NULL CHECK(degraded_after_ms>0),
 degraded INTEGER NOT NULL CHECK(degraded IN (0,1))
)`

type execQuerier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// decide is the rule of item 14. A failover that precedes the last contact
// (the standby's clock went back) cannot be compared: a degraded period is
// assumed, and the window starts at the failover.
func decide(epoch uint64, failover, contact time.Time, after time.Duration) Announcement {
	a := Announcement{Epoch: epoch, Failover: failover, LastContact: contact, DegradedAfter: after}
	if contact.IsZero() {
		return a
	}
	if failover.Sub(contact) >= after || failover.Before(contact) {
		a.Degraded = true
	}
	return a
}

func (a *Announcement) setBlanket(restoreAuthority string) {
	if a.Degraded {
		a.Blanket = authoritylog.BlanketID(restoreAuthority, a.Epoch)
	}
}

// blanket is the record's content.
func (a Announcement) blanket() authoritylog.Blanket {
	from := a.LastContact
	if from.After(a.Failover) {
		from = a.Failover
	}
	return authoritylog.Blanket{IssuedBefore: a.Failover, WindowFrom: from}
}

// readAnnouncement reads the decision the replica recorded with its
// promotion mark; found is false when it has none.
func readAnnouncement(ctx context.Context, q execQuerier, p Promotion) (Announcement, bool, error) {
	a := Announcement{Epoch: p.Epoch}
	if _, err := q.ExecContext(ctx, promotionSchema); err != nil {
		return a, false, err
	}
	var epoch, failover, after int64
	var contact sql.NullInt64
	var degraded bool
	err := q.QueryRowContext(ctx, "SELECT epoch,failover_at,contact_at,degraded_after_ms,degraded FROM replica_promotion WHERE singleton=1").
		Scan(&epoch, &failover, &contact, &after, &degraded)
	if errors.Is(err, sql.ErrNoRows) {
		return a, false, nil
	}
	if err != nil {
		return a, false, err
	}
	if uint64(epoch) != p.Epoch {
		return a, false, ErrConflict
	}
	a.Failover, a.DegradedAfter, a.Degraded = time.UnixMilli(failover), time.Duration(after)*time.Millisecond, degraded
	if contact.Valid {
		a.LastContact = time.UnixMilli(contact.Int64)
	}
	a.setBlanket(p.RestoreAuthority)
	return a, true, nil
}

// markPromoted marks the replica promoted, unless it is already, and
// records the announcement with the mark, unless it has one. A record that
// reached the replica since its state was read means that the old primary
// still runs (ErrStillReplicating).
func markPromoted(ctx context.Context, r *Replica, s replicaState, p Promotion, o PromoteOptions) (Announcement, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Announcement{}, err
	}
	defer tx.Rollback()
	a, found, err := readAnnouncement(ctx, tx, p)
	if err != nil {
		return a, err
	}
	if !s.promoted {
		result, err := tx.ExecContext(ctx, "UPDATE replica_state SET promoted=1 WHERE singleton=1 AND promoted=0 AND seq=?", s.seq)
		if err != nil {
			return a, err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return a, errors.Join(ErrStillReplicating, err)
		}
	}
	if !found {
		contact, err := lastContact(ctx, tx)
		if err != nil {
			return a, err
		}
		failover := time.UnixMilli(o.Now().UnixMilli())
		a = decide(p.Epoch, failover, contact, o.DegradedAfter)
		a.setBlanket(p.RestoreAuthority)
		var contactAt any
		if !contact.IsZero() {
			contactAt = contact.UnixMilli()
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO replica_promotion VALUES(1,?,?,?,?,?)",
			p.Epoch, failover.UnixMilli(), contactAt, o.DegradedAfter.Milliseconds(), a.Degraded); err != nil {
			return a, err
		}
	}
	return a, tx.Commit()
}

// insertBlanket writes the blanket record into the promoted catalogue, in
// the transaction that copies the replica. The promoted catalogue has no
// replica: the record carries sequence 0, as every record of a catalogue
// without one.
func insertBlanket(ctx context.Context, tx *sql.Tx, p Promotion) error {
	a := p.Announcement
	if !a.Degraded {
		return nil
	}
	objects, err := json.Marshal(a.blanket().Objects())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO main.access_revocations VALUES(?,?,?,?,?,?,0)",
		a.Blanket, authoritylog.AccessBlanket, "", string(objects), a.Failover.UnixMilli(), p.Epoch)
	return err
}

// checkBlanket checks a promoted catalogue against the announcement: it
// holds the blanket record when, and only when, a degraded period is
// assumed. An announcement of an earlier release, unknown, is not checked.
func checkBlanket(ctx context.Context, q querier, p Promotion) error {
	a := p.Announcement
	if a.Failover.IsZero() {
		return nil
	}
	id := authoritylog.BlanketID(p.RestoreAuthority, p.Epoch)
	var kind, objects string
	err := q.QueryRowContext(ctx, "SELECT kind,objects FROM access_revocations WHERE id=?", id).Scan(&kind, &objects)
	if errors.Is(err, sql.ErrNoRows) {
		if a.Degraded {
			return ErrConflict
		}
		return nil
	}
	if err != nil {
		return err
	}
	var parsed [][]string
	if err = json.Unmarshal([]byte(objects), &parsed); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	b, ok := authoritylog.ParseBlanket(parsed)
	want := a.blanket()
	if !a.Degraded || kind != authoritylog.AccessBlanket || !ok || !b.IssuedBefore.Equal(want.IssuedBefore) || !b.WindowFrom.Equal(want.WindowFrom) {
		return ErrConflict
	}
	return nil
}

// Announcement is what this catalogue announces for its epoch: a degraded
// period, its window and the blanket record when the promotion to this epoch
// wrote one; otherwise only the epoch. Epoch 1 was never promoted.
func (c *Catalog) Announcement(ctx context.Context) (Announcement, error) {
	var a Announcement
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		epoch, err := writerEpoch(ctx, tx)
		if err != nil {
			return err
		}
		a = Announcement{Epoch: epoch}
		if v, err := version(ctx, tx); err != nil || v < schemaVersion || epoch < 2 {
			return err
		}
		stored, err := accessRecord(ctx, tx, authoritylog.BlanketID(c.identity, epoch))
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		b, ok := authoritylog.ParseBlanket(stored.Objects)
		if !ok || stored.Kind != authoritylog.AccessBlanket {
			return ErrUnavailable
		}
		a.Degraded, a.Blanket, a.Failover, a.LastContact = true, stored.ID, b.IssuedBefore, b.WindowFrom
		return nil
	})
	return a, err
}
