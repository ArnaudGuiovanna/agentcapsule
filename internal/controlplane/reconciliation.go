package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/jackc/pgx/v5"
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

// ErrNotReconciled means that PostgreSQL has not been reconciled with the
// authority service's epoch: the API refuses to open until agentcapsule-admin
// reconcile has run.
var ErrNotReconciled = errors.New("database not reconciled with the authorities' epoch: run agentcapsule-admin reconcile")

// ErrReconciliationRecord means that the authority holds an access
// revocation record that this binary cannot replay. Nothing is marked
// reconciled.
var ErrReconciliationRecord = errors.New("access revocation record that cannot be replayed")

// ErrReconciliationConflict means that the authority service changed epoch
// during the run, does not hold its announced blanket record, or that this
// epoch was reconciled with other authorities. Nothing is marked reconciled.
var ErrReconciliationConflict = errors.New("reconciliation conflict: run it again, and check the pinned identities")

// AuthorityRecord is an access revocation record as the authority holds it.
type AuthorityRecord struct {
	AccessRecord
	RecordedAt time.Time
	Epoch, Seq uint64
	// OnReplica and Degraded are the record's progress, as on_replica gives it.
	OnReplica, Degraded bool
}

// AuthorityStore is a store as the authority knows it.
type AuthorityStore struct {
	ID, Volume  string
	Incarnation uint64
	Sealed      bool
}

// FailoverAnnouncement is what the promotion to an epoch announced.
type FailoverAnnouncement struct {
	Epoch uint64
	// Degraded: the promotion assumed that a degraded period ran. The window
	// from WindowFrom to WindowTo is announced, and Blanket is the record
	// that revokes every bearer token issued before WindowTo.
	Degraded             bool
	WindowFrom, WindowTo time.Time
	Blanket              string
}

// ReconciliationAuthority is the authority service, as the reconciliation
// reaches it on its API socket (internal/authorityclient).
type ReconciliationAuthority interface {
	// RecordAccess appends a record PostgreSQL holds and the authority
	// lacks.
	AccessRecorder
	// AuthorityEpoch gives the restore authority's identity and epoch.
	AuthorityEpoch(ctx context.Context) (string, uint64, error)
	AuthorityRecords(ctx context.Context) ([]AuthorityRecord, error)
	AuthoritySubjects(ctx context.Context) ([]string, error)
	AuthorityStores(ctx context.Context) ([]AuthorityStore, error)
	AuthorityAnnouncement(ctx context.Context) (FailoverAnnouncement, error)
	// ImportSubjects begins, in the authority, the subjects it lacks.
	ImportSubjects(ctx context.Context, subjects []string) error
}

// Reconciliation is what a run did and found.
type Reconciliation struct {
	Epoch            uint64 `json:"epoch"`
	RestoreAuthority string `json:"restore_authority_id"`
	// Announcement is set when the promotion assumed a degraded period.
	Announcement *ReconciledWindow `json:"announcement,omitempty"`
	// Replayed counts the records PostgreSQL lacked; Kept those it held
	// and the authority lacked. SubjectsKept and SubjectsCopied count the
	// same for the revocation subjects.
	Replayed       int `json:"records_replayed"`
	Kept           int `json:"records_kept"`
	SubjectsKept   int `json:"subjects_kept"`
	SubjectsCopied int `json:"subjects_copied"`
	// DeletionsResumed are the agents whose deletion PostgreSQL did not
	// know; Unresumed the ones it could not resume.
	DeletionsResumed []string          `json:"deletions_resumed"`
	Unresumed        []StoreDivergence `json:"deletions_not_resumed"`
	// Divergent are the stores whose registration or incarnation differs.
	Divergent    []StoreDivergence `json:"divergent_stores"`
	ReconciledAt time.Time         `json:"reconciled_at"`
}

// ReconciledWindow is the announcement of a degraded period: outcomes
// confirmed and revocations made in the window may be lost, and every bearer
// token issued before its end is revoked.
type ReconciledWindow struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Blanket string    `json:"blanket_revocation_id"`
}

// StoreDivergence is a store that PostgreSQL and the authority see apart.
type StoreDivergence struct {
	Store  string `json:"store"`
	Reason string `json:"reason"`
	// The incarnation each side holds; 0 when that side has none.
	Authority uint64 `json:"authority_incarnation,omitempty"`
	Database  uint64 `json:"database_incarnation,omitempty"`
}

// The reasons of a divergence.
const (
	DivergenceNotEnrolled   = "not_enrolled"   // the authority registered it; PostgreSQL does not know it
	DivergenceNotRegistered = "not_registered" // PostgreSQL enrolled it past installation; the authority does not know it
	DivergenceVolume        = "volume"         // their volumes differ
	DivergenceIncarnation   = "incarnation"    // their incarnations differ
	DivergenceUnknownAgent  = "unknown_agent"  // a deletion to resume, of an agent PostgreSQL does not know
	DivergencePhase         = "phase"          // a deletion to resume, of an agent in a phase no deletion starts from
)

// reconciler is the account a resumed deletion names as its requester.
const reconciler = "authority-reconciliation"

// recordTimeoutReconciling bounds the wait for the service on one write.
const recordTimeoutReconciling = 30 * time.Second

var subjectForm = regexp.MustCompile(`^(agent|request|event)/.+$`)

// Reconciled reports whether PostgreSQL has been reconciled with the
// authorities' epoch.
func (s *Store) Reconciled(ctx context.Context, epoch uint64) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM authority_reconciliations WHERE epoch=$1)`, int64(epoch)).Scan(&ok)
	return ok, err
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

// Reconcile brings PostgreSQL up to the authority behind a, then records
// that it reconciled the authority's epoch.
func (s *Store) Reconcile(ctx context.Context, a ReconciliationAuthority) (Reconciliation, error) {
	out := Reconciliation{DeletionsResumed: []string{}, Unresumed: []StoreDivergence{}, Divergent: []StoreDivergence{}}
	identity, epoch, err := a.AuthorityEpoch(ctx)
	if err != nil {
		return out, err
	}
	if !authoritylog.ValidID(identity, "restoreauth_") || epoch == 0 {
		return out, ErrInput
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
func (s *Store) keepOwnRecords(ctx context.Context, a ReconciliationAuthority, held map[string]bool) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,kind,coalesce(organization_id,''),objects FROM access_revocations ORDER BY recorded_at,id`)
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
		cancel()
		if err != nil || !receipt.Known {
			return 0, errors.Join(ErrAuthorityUnavailable, err)
		}
	}
	return len(missing), nil
}

// keepOwnSubjects begins in the authority every revocation subject of
// revocation_catalogue that it lacks.
func (s *Store) keepOwnSubjects(ctx context.Context, a ReconciliationAuthority, subjects []string) (int, error) {
	own, err := s.RevocationSubjects(ctx)
	if err != nil {
		return 0, err
	}
	var missing []string
	for _, subject := range own {
		if !slices.Contains(subjects, subject) {
			missing = append(missing, subject)
		}
	}
	for chunk := range slices.Chunk(missing, 500) {
		if err = a.ImportSubjects(ctx, chunk); err != nil {
			return 0, errors.Join(ErrAuthorityUnavailable, err)
		}
	}
	return len(missing), nil
}

// replayRecords replays, in their order, the records PostgreSQL lacks.
func (s *Store) replayRecords(ctx context.Context, records []AuthorityRecord) (int, error) {
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

// readerOf is the organization whose administrators and auditors read a
// revocation, as the revoking route sets it: empty for the platform's own.
func readerOf(kind, organization string) string {
	switch kind {
	case authoritylog.AccessMember, authoritylog.AccessPrincipal, authoritylog.AccessServiceToken, authoritylog.AccessTeam,
		authoritylog.AccessTeamMembership, authoritylog.AccessAssignment, authoritylog.AccessLLMProvider:
		return organization
	}
	return ""
}

func (s *Store) replayRecord(ctx context.Context, r AuthorityRecord) (bool, error) {
	if _, known := authoritylog.AccessBearer(r.Kind); !known || !authoritylog.ValidID(r.ID, "arv_") || !authoritylog.ValidAccessObjects(r.Objects) {
		return false, ErrReconciliationRecord
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_revocations WHERE id=$1)`, r.ID).Scan(&exists); err != nil || exists {
		return false, err
	}
	if err = replayEffect(ctx, tx, r); err != nil {
		return false, err
	}
	state := RevocationPending
	if confirmable(r.Kind, AccessReceipt{Known: true, OnReplica: r.OnReplica, Degraded: r.Degraded}) {
		state = RevocationConfirmed
	}
	objects, err := json.Marshal(r.Objects)
	if err != nil {
		return false, err
	}
	recorded := r.RecordedAt
	if recorded.IsZero() {
		recorded = time.Now()
	}
	if _, err = tx.Exec(ctx, `INSERT INTO access_revocations(id,tenant_id,organization_id,kind,objects,epoch,seq,state,recorded_at,confirmed_at)
        VALUES($1,nullif($2,''),nullif($3,''),$4,$5,$6,$7,$8,$9,CASE WHEN $8='confirmed' THEN clock_timestamp() END)`,
		r.ID, readerOf(r.Kind, r.Organization), r.Organization, r.Kind, objects, int64(r.Epoch), int64(r.Seq), state, recorded); err != nil {
		return false, err
	}
	return true, commit(ctx, tx)
}

// replayEffect makes PostgreSQL revoke what r revokes, as the revoking
// route did, in tx. An object PostgreSQL does not know was created in the
// window and lost with it: nothing grants access through it.
func replayEffect(ctx context.Context, tx pgx.Tx, r AuthorityRecord) error {
	org := r.Organization
	exec := func(sql string, args ...any) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}
	tenantScoped := r.Kind != authoritylog.AccessAPIToken && r.Kind != authoritylog.AccessPlatformCredential &&
		r.Kind != authoritylog.AccessMandate && r.Kind != authoritylog.AccessBlanket && r.Kind != authoritylog.AccessOrganization
	if tenantScoped && org == "" {
		return ErrReconciliationRecord
	}
	if r.Kind == authoritylog.AccessBlanket {
		b, ok := authoritylog.ParseBlanket(r.Objects)
		if !ok {
			return ErrReconciliationRecord
		}
		return replayBlanket(ctx, tx, b.IssuedBefore)
	}
	for _, o := range r.Objects {
		var err error
		switch {
		case r.Kind == authoritylog.AccessMember && len(o) == 1:
			if err = exec(`UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2 AND status<>'revoked'`, org, o[0]); err == nil {
				err = exec(`UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2 AND status<>'revoked'`, org, o[0])
			}
		case r.Kind == authoritylog.AccessPrincipal && len(o) == 1:
			if err = exec(`UPDATE principals SET status='disabled' WHERE tenant_id=$1 AND id=$2 AND status<>'disabled'`, org, o[0]); err == nil {
				err = exec(`UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2 AND status<>'revoked'`, org, o[0])
			}
		case r.Kind == authoritylog.AccessServiceToken && len(o) == 1:
			// revoked_by names a principal of the organization: the token's
			// issuer stands for the administrator whose revocation was lost.
			err = exec(`UPDATE service_tokens SET revoked_at=clock_timestamp(),revoked_by=issued_by
                WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, org, o[0])
		case r.Kind == authoritylog.AccessTeam && len(o) == 1:
			if err = exec(`UPDATE teams SET status='disabled' WHERE tenant_id=$1 AND id=$2 AND status<>'disabled'`, org, o[0]); err == nil {
				err = exec(`UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND team_id=$2 AND status='active'`, org, o[0])
			}
		case r.Kind == authoritylog.AccessTeamMembership && len(o) == 2:
			err = exec(`UPDATE team_memberships SET status='revoked' WHERE tenant_id=$1 AND team_id=$2 AND principal_id=$3 AND status='active'`, org, o[0], o[1])
		case r.Kind == authoritylog.AccessAssignment && len(o) == 1:
			err = exec(`UPDATE agent_assignments SET status='revoked',revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status='active'`, org, o[0])
		case r.Kind == authoritylog.AccessOrganization && len(o) == 1:
			err = exec(`UPDATE organizations SET status='disabled',policy_version=policy_version+1 WHERE id=$1 AND status<>'disabled'`, o[0])
		case r.Kind == authoritylog.AccessAPIToken && len(o) == 1:
			err = exec(`UPDATE api_tokens SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL`, o[0])
		case r.Kind == authoritylog.AccessPlatformCredential && len(o) == 1:
			err = exec(`UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL`, o[0])
		case r.Kind == authoritylog.AccessMandate && len(o) == 1:
			err = exec(`UPDATE mandates SET valid=false WHERE id=$1 AND valid`, o[0])
		case r.Kind == authoritylog.AccessLLMProvider && (len(o) == 1 || len(o) == 3 && o[1] == "generation"):
			// A disabled provider, or a rotated one: the database still
			// holding the revoked generation's credential disables the
			// provider, which cannot be enabled again. Its administrator
			// creates it again.
			generation := int64(1<<63 - 1)
			if len(o) == 3 {
				if generation, err = strconv.ParseInt(o[2], 10, 64); err != nil {
					return ErrReconciliationRecord
				}
			}
			var tag int64
			if err = tx.QueryRow(ctx, `WITH d AS (UPDATE llm_providers SET status='disabled',disabled_at=clock_timestamp(),secret_ciphertext='\x'::bytea
                WHERE tenant_id=$1 AND id=$2 AND status<>'disabled' AND secret_generation<=$3 RETURNING 1) SELECT count(*) FROM d`, org, o[0], generation).Scan(&tag); err == nil && tag > 0 {
				err = exec(`UPDATE llm_model_aliases SET status='disabled',disabled_at=clock_timestamp() WHERE tenant_id=$1 AND provider_id=$2 AND status='active'`, org, o[0])
			}
		case r.Kind == authoritylog.AccessDelegatedToken && len(o) == 2:
			if err = exec(`INSERT INTO delegation_issuers(tenant_id,issuer) SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM organizations WHERE id=$1)
                ON CONFLICT DO NOTHING`, org, o[0]); err == nil {
				err = exec(`INSERT INTO delegation_revocations(tenant_id,issuer,token_id)
                    SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM delegation_issuers WHERE tenant_id=$1 AND issuer=$2) ON CONFLICT DO NOTHING`, org, o[0], o[1])
			}
		case r.Kind == authoritylog.AccessDelegationTrust:
			err = replayTrust(ctx, tx, org, o)
		default:
			return ErrReconciliationRecord
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// replayTrust replays a delegation trust's revocation: the trust revoked;
// a rotation, whose new keys the database lost, revokes the trust while it
// is of an earlier generation, until the operator rotates it again; a
// retired key's end.
func replayTrust(ctx context.Context, tx pgx.Tx, org string, o []string) error {
	switch {
	case len(o) == 2:
		_, err := tx.Exec(ctx, `UPDATE delegation_trusts SET status='revoked',updated_at=clock_timestamp()
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND status<>'revoked'`, org, o[0], o[1])
		return err
	case len(o) == 4 && o[2] == "generation":
		generation, err := strconv.ParseInt(o[3], 10, 64)
		if err != nil {
			return ErrReconciliationRecord
		}
		_, err = tx.Exec(ctx, `UPDATE delegation_trusts SET status='revoked',updated_at=clock_timestamp()
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND status<>'revoked' AND generation<$4`, org, o[0], o[1], generation)
		return err
	case (len(o) == 4 || len(o) == 5) && o[2] == "key":
		var end any = nil
		if len(o) == 5 {
			t, err := time.Parse(time.RFC3339Nano, o[4])
			if err != nil {
				return ErrReconciliationRecord
			}
			end = t
		}
		tag, err := tx.Exec(ctx, `UPDATE delegation_keys SET expires_at=coalesce($5::timestamptz,clock_timestamp())
            WHERE tenant_id=$1 AND issuer=$2 AND audience=$3 AND key_id=$4 AND retired_at IS NULL
              AND (expires_at IS NULL OR expires_at>coalesce($5::timestamptz,clock_timestamp()))`, org, o[0], o[1], o[3], end)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		// A key whose end has passed leaves the trust's key set now.
		if _, err = settleKeys(ctx, tx, org, o[0], o[1], nil); errors.Is(err, ErrTransition) {
			err = nil
		}
		return err
	}
	return ErrReconciliationRecord
}

// replayBlanket revokes every bearer token issued before the failover, and
// moves every delegation trust's minimum_iat past it: a delegated token's iat
// is a whole second, so the second of the failover is refused too.
func replayBlanket(ctx context.Context, tx pgx.Tx, failover time.Time) error {
	for _, sql := range []string{
		`UPDATE api_tokens SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND created_at<$1`,
		`UPDATE service_tokens SET revoked_at=clock_timestamp(),revoked_by=issued_by WHERE revoked_at IS NULL AND created_at<$1`,
		`UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND created_at<$1`,
		`UPDATE applications SET minimum_iat=greatest(minimum_iat,date_trunc('second',$1::timestamptz)+interval '1 second')`,
		`UPDATE delegation_trusts SET minimum_iat=date_trunc('second',$1::timestamptz)+interval '1 second',updated_at=clock_timestamp()
            WHERE minimum_iat<date_trunc('second',$1::timestamptz)+interval '1 second'`,
	} {
		if _, err := tx.Exec(ctx, sql, failover); err != nil {
			return err
		}
	}
	return nil
}

// copySubjects inserts the authority's revocation subjects into
// revocation_catalogue. A subject of another form than PostgreSQL's is left
// out: no PostgreSQL row can name it.
func (s *Store) copySubjects(ctx context.Context, subjects []string) (int, error) {
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
		tag, err := s.pool.Exec(ctx, `INSERT INTO revocation_catalogue(subject) SELECT unnest($1::text[]) ON CONFLICT DO NOTHING`, valid)
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
func (s *Store) resumeDeletions(ctx context.Context, stores []AuthorityStore, subjects []string, out *Reconciliation) error {
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

// divergentStores compares the authority's stores with store_enrollments.
// A store PostgreSQL enrolled and the authority does not know is reported
// only past installation: before, the authority's registration may still
// come.
func (s *Store) divergentStores(ctx context.Context, stores []AuthorityStore) ([]StoreDivergence, error) {
	type enrolled struct {
		volume, stage string
		incarnation   uint64
	}
	rows, err := s.pool.Query(ctx, `SELECT agent_id,volume_id,incarnation,stage FROM store_enrollments ORDER BY agent_id`)
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
func (s *Store) recordReconciliation(ctx context.Context, out *Reconciliation) error {
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
	err = s.pool.QueryRow(ctx, `INSERT INTO authority_reconciliations AS r(epoch,restore_authority_id,degraded,window_from,window_to,blanket_revocation_id,report)
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
