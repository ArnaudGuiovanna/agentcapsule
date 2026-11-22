// Package reconciliation reconciles durable access and store state with the authority after a failover.
package reconciliation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The reconciliation of PostgreSQL with the authorities after a failover
// (docs/adr/005-keys-outside-restored-domain.md, "What the code must do",
// items 14 and 15; docs/adr/006-authority-service.md §7, wave 7). The
// promotion of the authorities takes a new epoch; PostgreSQL, promoted from
// its own older copy, may lack what they hold by the database's window. Before
// the API opens (REPLAY_FIRST), agentcapsule-admin reconcile:
//
//  1. keeps PostgreSQL's own access revocation records and revocation
//     subjects in the authority, so that one the WAL shipped and the old
//     primary's authority lost survives;
//  2. replays into PostgreSQL every access revocation record it lacks, in
//     the order they were recorded, each with its effect, in one transaction;
//  3. copies the revocation subjects into revocation_catalogue;
//  4. resumes the deletion of every agent whose store the authority sealed,
//     or whose agent/ subject it holds;
//  5. reports every store whose registration or incarnation differs;
//  6. records that it reconciled the authority's epoch.
//
// A record PostgreSQL holds needs no replay: its row commits with the
// revocation's effect. A record it lacks was lost with every later commit
// (the WAL is a prefix), so replaying it undoes no later grant. Each step can
// be repeated, and an interrupted run is run again from the start.

type rowReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}
type database interface {
	rowReader
	Query(context.Context, string, ...any) (pgx.Rows, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// Each record replay and each deletion is an independent durable operation.
// RPCs to the authority run between transactions.
type recovery struct {
	db             database
	replayRecord   func(context.Context, AuthorityRecord) (bool, error)
	resumeDeletion func(context.Context, string) (bool, string, error)
}

// recordTimeoutReconciling bounds the wait for the service on one write.
const recordTimeoutReconciling = 30 * time.Second

var subjectForm = regexp.MustCompile(`^(agent|request|event)/.+$`)

// Reconciled reports whether PostgreSQL has been reconciled with the
// authorities' epoch.
func Reconciled(ctx context.Context, db rowReader, epoch uint64) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM authority_reconciliations WHERE epoch=$1)`, int64(epoch)).Scan(&ok)
	return ok, err
}

// Reconcile brings PostgreSQL up to the authority behind a, then records
// that it reconciled the authority's epoch.
func Reconcile(ctx context.Context, db database, a ReconciliationAuthority,
	replay func(context.Context, AuthorityRecord) (bool, error),
	resumeDeletion func(context.Context, string) (bool, string, error)) (Reconciliation, error) {
	s := recovery{db: db, replayRecord: replay, resumeDeletion: resumeDeletion}
	out := Reconciliation{DeletionsResumed: []string{}, Unresumed: []StoreDivergence{}, Divergent: []StoreDivergence{}}
	identity, epoch, err := a.AuthorityEpoch(ctx)
	if err != nil {
		return out, err
	}
	if !authoritylog.ValidID(identity, "restoreauth_") || epoch == 0 {
		return out, persistence.ErrInput
	}
	out.Epoch, out.RestoreAuthority = epoch, identity
	records, err := a.AuthorityRecords(ctx)
	if err != nil {
		return out, err
	}
	subjects, err := a.AuthoritySubjects(ctx)
	if err != nil {
		return out, err
	}
	stores, err := a.AuthorityStores(ctx)
	if err != nil {
		return out, err
	}
	announcement, err := a.AuthorityAnnouncement(ctx)
	if err != nil {
		return out, err
	}
	if announcement.Epoch != epoch {
		return out, ErrReconciliationConflict // the service changed epoch meanwhile
	}
	held := make(map[string]bool, len(records))
	for _, r := range records {
		held[r.ID] = true
	}
	if announcement.Degraded && !held[announcement.Blanket] {
		return out, ErrReconciliationConflict
	}
	if out.Kept, err = s.keepOwnRecords(ctx, a, held); err != nil {
		return out, err
	}
	if out.SubjectsKept, err = s.keepOwnSubjects(ctx, a, subjects); err != nil {
		return out, err
	}
	if out.Replayed, err = s.replayRecords(ctx, records); err != nil {
		return out, err
	}
	if out.SubjectsCopied, err = s.copySubjects(ctx, subjects); err != nil {
		return out, err
	}
	if err = s.resumeDeletions(ctx, stores, subjects, &out); err != nil {
		return out, err
	}
	if out.Divergent, err = s.divergentStores(ctx, stores); err != nil {
		return out, err
	}
	if announcement.Degraded {
		out.Announcement = &ReconciledWindow{From: announcement.WindowFrom, To: announcement.WindowTo, Blanket: announcement.Blanket}
	}
	return out, s.recordReconciliation(ctx, &out)
}

// keepOwnRecords appends to the authority every record PostgreSQL holds
// and the authority lacks.
func (s recovery) keepOwnRecords(ctx context.Context, a ReconciliationAuthority, held map[string]bool) (int, error) {
	rows, err := s.db.Query(ctx, `SELECT id,kind,coalesce(organization_id,''),objects FROM access_revocations ORDER BY recorded_at,id`)
	if err != nil {
		return 0, err
	}
	var missing []AccessRecord
	for rows.Next() {
		var r AccessRecord
		var objects []byte
		if err = rows.Scan(&r.ID, &r.Kind, &r.Organization, &objects); err != nil {
			rows.Close()
			return 0, err
		}
		if held[r.ID] {
			continue
		}
		if err = json.Unmarshal(objects, &r.Objects); err != nil {
			rows.Close()
			return 0, err
		}
		missing = append(missing, r)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range missing {
		wait, cancel := context.WithTimeout(ctx, recordTimeoutReconciling)
		receipt, err := a.RecordAccess(wait, r)
		if err == nil && receipt.Known {
			// A revocation whose recording did not succeed after its
			// commit is recorded now.
			if _, _, ok := SettleReceipt(wait, s.db, r.ID, r.Kind, receipt); !ok {
				err = errors.New("the revocation's row could not be updated")
			}
		}
		cancel()
		if err != nil || !receipt.Known {
			return 0, errors.Join(ErrAuthorityUnavailable, err)
		}
	}
	return len(missing), nil
}

// keepOwnSubjects begins in the authority every revocation subject of
// revocation_catalogue that it lacks.
func (s recovery) keepOwnSubjects(ctx context.Context, a ReconciliationAuthority, subjects []string) (int, error) {
	own, err := Subjects(ctx, s.db)
	if err != nil {
		return 0, err
	}
	var missing []string
	for _, subject := range own {
		if !slices.Contains(subjects, subject) {
			missing = append(missing, subject)
		}
	}
	scoped, ok := a.(ScopedImporter)
	for chunk := range slices.Chunk(missing, 500) {
		if ok {
			// Each in its scope (revocation_scopes.go), not every store's.
			var scopes []RevocationScope
			if scopes, err = Scopes(ctx, s.db, chunk); err != nil {
				return 0, err
			}
			err = scoped.ImportScopes(ctx, scopes)
		} else {
			err = a.ImportSubjects(ctx, chunk)
		}
		if err != nil {
			return 0, errors.Join(ErrAuthorityUnavailable, err)
		}
	}
	return len(missing), nil
}

// replayRecords replays, in their order, the records PostgreSQL lacks.
func (s recovery) replayRecords(ctx context.Context, records []AuthorityRecord) (int, error) {
	replayed := 0
	for _, r := range records {
		done, err := s.replayRecord(ctx, r)
		if err != nil {
			return replayed, fmt.Errorf("replay %s: %w", r.ID, err)
		}
		if done {
			replayed++
		}
	}
	return replayed, nil
}

// copySubjects inserts the authority's revocation subjects into
// revocation_catalogue. A subject of another form than PostgreSQL's is left
// out: no PostgreSQL row can name it.
func (s recovery) copySubjects(ctx context.Context, subjects []string) (int, error) {
	copied := 0
	for chunk := range slices.Chunk(subjects, 500) {
		var valid []string
		for _, subject := range chunk {
			if subjectForm.MatchString(subject) {
				valid = append(valid, subject)
			}
		}
		if len(valid) == 0 {
			continue
		}
		tag, err := s.db.Exec(ctx, `INSERT INTO revocation_catalogue(subject) SELECT unnest($1::text[]) ON CONFLICT DO NOTHING`, valid)
		if err != nil {
			return copied, err
		}
		copied += int(tag.RowsAffected())
	}
	return copied, nil
}

// resumeDeletions requests again the deletion of every agent whose store
// the authority sealed, or whose agent/ subject it holds, when PostgreSQL
// does not know that deletion: the authority holds such a subject only once
// PostgreSQL had committed the deletion's request. The worker then carries
// the deletion on, as any other.
func (s recovery) resumeDeletions(ctx context.Context, stores []AuthorityStore, subjects []string, out *Reconciliation) error {
	var agents []string
	for _, st := range stores {
		if st.Sealed {
			agents = append(agents, st.ID)
		}
	}
	for _, subject := range subjects {
		if id, ok := strings.CutPrefix(subject, "agent/"); ok && id != "" {
			agents = append(agents, id)
		}
	}
	slices.Sort(agents)
	for _, id := range slices.Compact(agents) {
		resumed, reason, err := s.resumeDeletion(ctx, id)
		if err != nil {
			return err
		}
		switch {
		case resumed:
			out.DeletionsResumed = append(out.DeletionsResumed, id)
		case reason != "":
			out.Unresumed = append(out.Unresumed, StoreDivergence{Store: id, Reason: reason})
		}
	}
	return nil
}

// divergentStores compares the authority's stores with store_enrollments.
// A store PostgreSQL enrolled and the authority does not know is reported
// only past installation: before, the authority's registration may still
// come.
func (s recovery) divergentStores(ctx context.Context, stores []AuthorityStore) ([]StoreDivergence, error) {
	type enrolled struct {
		volume, stage string
		incarnation   uint64
	}
	rows, err := s.db.Query(ctx, `SELECT agent_id,volume_id,incarnation,stage FROM store_enrollments ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	database := map[string]enrolled{}
	for rows.Next() {
		var id string
		var e enrolled
		var incarnation int64
		if err = rows.Scan(&id, &e.volume, &incarnation, &e.stage); err != nil {
			rows.Close()
			return nil, err
		}
		e.incarnation = uint64(incarnation)
		database[id] = e
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out := []StoreDivergence{}
	known := map[string]bool{}
	for _, st := range stores {
		known[st.ID] = true
		e, ok := database[st.ID]
		switch {
		case !ok:
			out = append(out, StoreDivergence{Store: st.ID, Reason: DivergenceNotEnrolled, Authority: st.Incarnation})
		case e.volume != st.Volume:
			out = append(out, StoreDivergence{Store: st.ID, Reason: DivergenceVolume, Authority: st.Incarnation, Database: e.incarnation})
		case e.incarnation != st.Incarnation:
			out = append(out, StoreDivergence{Store: st.ID, Reason: DivergenceIncarnation, Authority: st.Incarnation, Database: e.incarnation})
		}
	}
	for id, e := range database {
		if !known[id] && e.stage != "INSTALLING" {
			out = append(out, StoreDivergence{Store: id, Reason: DivergenceNotRegistered, Database: e.incarnation})
		}
	}
	slices.SortFunc(out, func(a, b StoreDivergence) int { return strings.Compare(a.Store, b.Store) })
	return out, nil
}

// recordReconciliation records that PostgreSQL is reconciled with out's
// epoch, with what the run found. A row of the same epoch for another
// restore authority is a conflict.
func (s recovery) recordReconciliation(ctx context.Context, out *Reconciliation) error {
	report, err := json.Marshal(struct {
		Replayed         int               `json:"records_replayed"`
		Kept             int               `json:"records_kept"`
		SubjectsKept     int               `json:"subjects_kept"`
		SubjectsCopied   int               `json:"subjects_copied"`
		DeletionsResumed []string          `json:"deletions_resumed"`
		Unresumed        []StoreDivergence `json:"deletions_not_resumed"`
		Divergent        []StoreDivergence `json:"divergent_stores"`
	}{out.Replayed, out.Kept, out.SubjectsKept, out.SubjectsCopied, out.DeletionsResumed, out.Unresumed, out.Divergent})
	if err != nil {
		return err
	}
	var from, to any
	var blanket any
	if w := out.Announcement; w != nil {
		from, to, blanket = w.From, w.To, w.Blanket
	}
	err = s.db.QueryRow(ctx, `INSERT INTO authority_reconciliations AS r(epoch,restore_authority_id,degraded,window_from,window_to,blanket_revocation_id,report)
        VALUES($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (epoch) DO UPDATE SET restore_authority_id=excluded.restore_authority_id,degraded=excluded.degraded,
          window_from=excluded.window_from,window_to=excluded.window_to,blanket_revocation_id=excluded.blanket_revocation_id,
          report=excluded.report,reconciled_at=clock_timestamp()
        WHERE r.restore_authority_id IS NULL OR r.restore_authority_id=excluded.restore_authority_id
        RETURNING reconciled_at`, int64(out.Epoch), out.RestoreAuthority, out.Announcement != nil, from, to, blanket, report).Scan(&out.ReconciledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrReconciliationConflict
	}
	return err
}
