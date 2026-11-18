//go:build linux && cgo

package restoreauthority

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
)

// Access revocation records (docs/adr/005-keys-outside-restored-domain.md,
// "What the code must do", items 6 to 8; docs/adr/006-authority-service.md
// §7, wave 5). Every transaction that revokes access appends one before its
// PostgreSQL commit. The record is a write of its own kind
// (authoritylog.WriteAccess), replicated like every write of the
// authorities, and it continues in degraded mode: the revocation takes
// effect at once on the primary. Whether the API may confirm it is the
// caller's rule (AccessReceipt). Records are never changed or deleted.

// accessSchema is version 4: the access revocation records, and the event
// ID of each outcome record (ADR 005, item 8). Each record keeps what the
// reconciliation after a failover replays (ADR 006 wave 7): its kind, the
// organization, the revoked objects, when it was recorded, and the epoch and
// sequence number of the stream's record that carried it (sequence 0 when
// no replica was armed).
const accessSchema = `
CREATE TABLE access_revocations (
 id TEXT PRIMARY KEY NOT NULL,
 kind TEXT NOT NULL,
 organization TEXT NOT NULL,
 objects TEXT NOT NULL,
 recorded_at INTEGER NOT NULL CHECK(recorded_at>0),
 epoch INTEGER NOT NULL CHECK(epoch>0),
 seq INTEGER NOT NULL CHECK(seq>=0)
);
CREATE TABLE outcome_events (
 outcome TEXT PRIMARY KEY NOT NULL REFERENCES outcomes(id),
 event TEXT NOT NULL
);
CREATE TRIGGER access_revocations_never_updated BEFORE UPDATE ON access_revocations BEGIN SELECT RAISE(ABORT,'access revocation is permanent'); END;
CREATE TRIGGER access_revocations_never_deleted BEFORE DELETE ON access_revocations BEGIN SELECT RAISE(ABORT,'access revocation is permanent'); END;
CREATE TRIGGER outcome_events_never_updated BEFORE UPDATE ON outcome_events BEGIN SELECT RAISE(ABORT,'outcome event is permanent'); END;
PRAGMA user_version=4;
`

// ErrUpgradeRequired means that the catalogue's schema is older than this
// binary's: run agentcapsule-admin init-restore-authority, with the
// authority service stopped. It is also ErrUnavailable.
var ErrUpgradeRequired = errors.Join(ErrUnavailable, errors.New("restore authority schema older than this binary: upgrade it"))

// CheckSchema refuses a catalogue whose schema is older than this binary's.
// Open accepts one, so that the upgrade can open it; the authority service
// checks it at start.
func (c *Catalog) CheckSchema(ctx context.Context) error {
	return c.run(ctx, false, func(tx *sql.Tx) error {
		v, err := version(ctx, tx)
		if err == nil && v < schemaVersion {
			err = ErrUpgradeRequired
		}
		return err
	})
}

// AccessRecord is one access revocation record.
type AccessRecord struct {
	// ID is the caller's: "arv_" and 32 hexadecimal digits. Appending the
	// same record again changes nothing; another record under the same ID
	// is refused (ErrConflict).
	ID string `json:"id"`
	// Kind is one of authoritylog.AccessKinds.
	Kind string `json:"kind"`
	// Organization is the organization whose access it revokes; empty for
	// the legacy owner domain and the platform's own credentials.
	Organization string `json:"organization,omitempty"`
	// Objects are the revoked objects, each named by the parts of its
	// identity, as docs/api/README.md lists them by kind.
	Objects [][]string `json:"objects"`
	// The authority sets these: when it recorded the record, in Unix
	// milliseconds, and the epoch and sequence number of the stream's record
	// that carried it.
	RecordedAt int64  `json:"recorded_at_ms,omitempty"`
	Epoch      uint64 `json:"epoch,omitempty"`
	Seq        uint64 `json:"seq,omitempty"`
}

// AccessReceipt says how far an access revocation record has gone.
type AccessReceipt struct {
	// Known is false when this authority holds no record of that ID: it was
	// never committed here, or it was lost with an old primary.
	Known bool   `json:"known"`
	Epoch uint64 `json:"epoch,omitempty"`
	Seq   uint64 `json:"seq,omitempty"`
	// OnReplica: the record needs nothing more. The replica holds it, or no
	// replica exists (standalone mode, or a promoted authority before a new
	// standby): in the model's terms the write is acknowledged.
	OnReplica bool `json:"on_replica"`
	// Degraded: the record was committed on the primary in degraded mode,
	// and the replica does not hold it yet.
	Degraded bool `json:"degraded"`
}

func validAccess(r AccessRecord) bool {
	_, known := authoritylog.AccessBearer(r.Kind)
	return known && authoritylog.ValidID(r.ID, "arv_") && (r.Organization == "" || authoritylog.ValidAccessText(r.Organization)) &&
		authoritylog.ValidAccessObjects(r.Objects)
}

// AppendAccess commits the record in the catalogue, then waits for the
// replica until ctx ends. It fails only when the record was not committed:
// the caller then commits nothing in PostgreSQL. Once committed, it returns
// the receipt: on the replica, committed in degraded mode, or neither when
// the wait ended first (the replica is slow, unreachable before degraded
// mode begins, or refused the record). A record that is already known
// returns its receipt as it stands.
func (c *Catalog) AppendAccess(ctx context.Context, r AccessRecord) (AccessReceipt, error) {
	if !validAccess(r) {
		return AccessReceipt{}, ErrInput
	}
	objects, err := json.Marshal(r.Objects)
	if err != nil {
		return AccessReceipt{}, errors.Join(ErrInput, err)
	}
	var stored AccessRecord
	done, err := c.commitLoop(ctx, true, authoritylog.WriteAccess, func(tx *sql.Tx) error {
		if v, err := version(ctx, tx); err != nil || v < schemaVersion {
			return errors.Join(ErrUpgradeRequired, err)
		}
		epoch, err := writerEpoch(ctx, tx)
		if err != nil {
			return err
		}
		var seq uint64
		if rec := c.recordingOf(tx); rec != nil && rec.state.armed() {
			seq = rec.state.seq + 1 // the record this transaction appends
		}
		result, err := c.exec(ctx, tx, stmtAccess, r.ID, r.Kind, r.Organization, string(objects), time.Now().UnixMilli(), epoch, seq)
		if err != nil {
			return err
		}
		if _, err = result.RowsAffected(); err != nil {
			return err
		}
		stored, err = accessRecord(ctx, tx, r.ID)
		if err != nil {
			return err
		}
		if stored.Kind != r.Kind || stored.Organization != r.Organization || !slices.EqualFunc(stored.Objects, r.Objects, func(x, y []string) bool { return slices.Equal(x, y) }) {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return AccessReceipt{}, err
	}
	receipt := AccessReceipt{Known: true, Epoch: stored.Epoch, Seq: stored.Seq}
	if done.record.Seq == 0 {
		// Nothing new reached the log: no replica is armed, or the record
		// was known.
		receipt.OnReplica, receipt.Degraded = c.accessProgress(stored)
		return receipt, nil
	}
	// Committed: wait for the replica up to the caller's deadline. In
	// degraded mode the record returns at once, as a degraded write.
	ackErr := c.repl.acknowledge(ctx, c, done.epoch, done.record, authoritylog.WriteAccess)
	receipt.OnReplica = c.repl.caughtUp(done.epoch, done.record.Seq)
	receipt.Degraded = !receipt.OnReplica && ackErr == nil
	return receipt, nil
}

// AccessStatus returns the receipt of the record id as it stands: the
// API's later question, once it reported the revocation as pending. An
// unknown record is not an error: Known is false.
func (c *Catalog) AccessStatus(ctx context.Context, id string) (AccessReceipt, error) {
	if !authoritylog.ValidID(id, "arv_") {
		return AccessReceipt{}, ErrInput
	}
	var stored AccessRecord
	found := false
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if v, err := version(ctx, tx); err != nil || v < schemaVersion {
			return errors.Join(ErrUpgradeRequired, err)
		}
		var err error
		stored, err = accessRecord(ctx, tx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil || !found {
		return AccessReceipt{}, err
	}
	receipt := AccessReceipt{Known: true, Epoch: stored.Epoch, Seq: stored.Seq}
	receipt.OnReplica, receipt.Degraded = c.accessProgress(stored)
	return receipt, nil
}

// accessProgress says whether the replica holds a committed record, or
// whether it waits for it in degraded mode.
func (c *Catalog) accessProgress(r AccessRecord) (onReplica, degraded bool) {
	if c.repl == nil {
		return true, false // no replica: nothing more to wait for
	}
	current, ok := c.repl.position(r.Epoch)
	if !ok {
		c.repl.mu.Lock()
		older := c.repl.valid && c.repl.known.Epoch > r.Epoch
		c.repl.mu.Unlock()
		if older {
			// A record of an older epoch reached this catalogue through
			// the promotion of the replica that held it, and the snapshot
			// that seeded the current standby copied it.
			return true, false
		}
		return false, c.repl.degraded(r.Epoch)
	}
	if current >= r.Seq {
		return true, false
	}
	return false, c.repl.degraded(r.Epoch)
}

func accessRecord(ctx context.Context, tx *sql.Tx, id string) (AccessRecord, error) {
	r := AccessRecord{ID: id}
	var objects string
	err := tx.QueryRowContext(ctx, "SELECT kind,organization,objects,recorded_at,epoch,seq FROM access_revocations WHERE id=?", id).
		Scan(&r.Kind, &r.Organization, &objects, &r.RecordedAt, &r.Epoch, &r.Seq)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal([]byte(objects), &r.Objects); err != nil {
		return r, errors.Join(ErrUnavailable, err)
	}
	return r, nil
}

// AccessRecords lists the access revocation records this catalogue holds,
// in the order they were recorded. Tests and the reconciliation of ADR 006
// wave 7 read them.
func (c *Catalog) AccessRecords(ctx context.Context) ([]AccessRecord, error) {
	var out []AccessRecord
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if v, err := version(ctx, tx); err != nil || v < schemaVersion {
			return errors.Join(ErrUpgradeRequired, err)
		}
		var err error
		out, err = readAccessRecords(ctx, tx)
		return err
	})
	return out, err
}

func readAccessRecords(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]AccessRecord, error) {
	rows, err := q.QueryContext(ctx, "SELECT id,kind,organization,objects,recorded_at,epoch,seq FROM access_revocations ORDER BY epoch,seq,recorded_at,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccessRecord{}
	for rows.Next() {
		var r AccessRecord
		var objects string
		if err = rows.Scan(&r.ID, &r.Kind, &r.Organization, &objects, &r.RecordedAt, &r.Epoch, &r.Seq); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(objects), &r.Objects); err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AccessRecords lists the access revocation records the replica holds.
func (r *Replica) AccessRecords(ctx context.Context) ([]AccessRecord, error) {
	return readAccessRecords(ctx, r.db)
}

// recordEvent keeps the event ID of a recorded outcome, on a catalogue of
// schema version 4. The outcome ID is derived from its store and event, so
// one outcome has one event: another is a conflict.
func (c *Catalog) recordEvent(ctx context.Context, tx *sql.Tx, outcome Outcome) error {
	if outcome.Event == "" {
		return nil
	}
	if v, err := version(ctx, tx); err != nil || v < schemaVersion {
		return err
	}
	if _, err := c.exec(ctx, tx, stmtOutcomeEvent, outcome.ID, outcome.Event); err != nil {
		return err
	}
	var event string
	if err := tx.QueryRowContext(ctx, "SELECT event FROM outcome_events WHERE outcome=?", outcome.ID).Scan(&event); err != nil {
		return err
	}
	if event != outcome.Event {
		return ErrConflict
	}
	return nil
}
