package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
)

// Access revocation records (docs/adr/006-authority-service.md §7, wave 5;
// docs/adr/005-keys-outside-restored-domain.md, items 6 and 7). Every
// transaction that revokes access appends a record to the authority service
// before it commits: a record the service did not commit fails the request,
// and nothing is committed here (ErrAuthorityUnavailable). The API confirms
// a revocation once the standby's replica holds its record, or at once when
// it is a bearer token's and the service runs in degraded mode: the blanket
// revocation of every bearer token at a failover covers it. Otherwise the
// revocation is pending: it took effect here and on the primary's
// authorities, and ConfirmAccessRevocations confirms it later.

// ErrAuthorityUnavailable means that the authority service did not record a
// revocation: it does not answer, or the standby holds its record back
// before degraded mode begins. Nothing was committed: try again in a moment.
var ErrAuthorityUnavailable = errors.New("authority service did not record the revocation: try again")

// The states of an access revocation.
const (
	RevocationPending   = "pending"
	RevocationConfirmed = "confirmed"
)

// AccessRecord is the record a revoking transaction appends: its kind (one of
// authoritylog.AccessKinds), the organization whose access it revokes, and
// the revoked objects, each named by the parts of its identity.
type AccessRecord struct {
	ID           string
	Kind         string
	Organization string
	Objects      [][]string
}

// AccessReceipt is the authority service's answer about a record.
type AccessReceipt struct {
	// Known is false when the service holds no record of that ID.
	Known      bool
	Epoch, Seq uint64
	// OnReplica: the standby's replica holds the record, or no replica
	// exists. Degraded: the record was committed in degraded mode, and the
	// replica does not hold it yet.
	OnReplica, Degraded bool
}

// AccessRecorder is the authority service, as the API and agentcapsule-admin
// reach it (internal/authorityclient).
type AccessRecorder interface {
	// RecordAccess appends r: the service commits it, then waits for the
	// replica until ctx's deadline. An error means that it may not have
	// committed it.
	RecordAccess(ctx context.Context, r AccessRecord) (AccessReceipt, error)
	// AccessProgress asks how far the record id has gone.
	AccessProgress(ctx context.Context, id string) (AccessReceipt, error)
}

type accessRecorder struct{ AccessRecorder }

// RecordAccessWith makes every revoking transaction append its record to r
// before it commits. Without it (development without the authority
// service), revocations are recorded in PostgreSQL only, and their answers
// carry no revocation state.
func (s *Store) RecordAccessWith(r AccessRecorder) {
	if r == nil {
		s.access.Store(nil)
		return
	}
	s.access.Store(&accessRecorder{r})
}

func (s *Store) recorder() AccessRecorder {
	if r := s.access.Load(); r != nil {
		return r.AccessRecorder
	}
	return nil
}

// AccessRevocation is a revocation as the API reports it.
type AccessRevocation struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	State       string     `json:"state"`
	RecordedAt  time.Time  `json:"recorded_at"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}

// recordTimeout bounds the wait for the authority service in a revoking
// transaction, within the request's own deadline: the service waits for the
// replica until then, and the transaction holds its locks meanwhile.
const recordTimeout = 5 * time.Second

// confirmable is the API's rule: the replica holds the record, or it is a
// bearer token's and the service runs in degraded mode.
func confirmable(kind string, r AccessReceipt) bool {
	bearer, _ := authoritylog.AccessBearer(kind)
	return r.Known && (r.OnReplica || (bearer && r.Degraded))
}

// revocations collects the records one revoking transaction appends.
type revocations struct {
	store *Store
	tx    pgx.Tx
	// reader is the organization whose administrators and auditors read
	// them; empty for the platform's own revocations.
	reader string
	list   []AccessRevocation
}

func (s *Store) revocations(tx pgx.Tx, reader string) *revocations {
	return &revocations{store: s, tx: tx, reader: reader}
}

// add appends the record of kind for objects to the authority service, then
// inserts its row, in the caller's transaction, before its commit. Nothing
// to revoke appends nothing; nor does a store without the authority service.
func (r *revocations) add(ctx context.Context, kind, organization string, objects [][]string) error {
	if len(objects) == 0 || r.store.recorder() == nil {
		return nil
	}
	// A record carries at most MaxAccessObjects objects, and stays well
	// within a record of the stream: a long list goes in several records.
	size, start := 0, 0
	for i, o := range objects {
		encoded, err := json.Marshal(o)
		if err != nil {
			return err
		}
		if i > start && (i-start == authoritylog.MaxAccessObjects || size+len(encoded) > maxRecordObjects) {
			if err = r.addOne(ctx, kind, organization, objects[start:i]); err != nil {
				return err
			}
			size, start = 0, i
		}
		size += len(encoded) + 1
	}
	return r.addOne(ctx, kind, organization, objects[start:])
}

// maxRecordObjects bounds the encoded objects of one record, far below a
// stream record's 64 KiB.
const maxRecordObjects = 16 << 10

func (r *revocations) addOne(ctx context.Context, kind, organization string, objects [][]string) error {
	recorder := r.store.recorder()
	if _, known := authoritylog.AccessBearer(kind); !known || !authoritylog.ValidAccessObjects(objects) ||
		(organization != "" && !authoritylog.ValidAccessText(organization)) {
		return ErrInput
	}
	record := AccessRecord{ID: newID("arv"), Kind: kind, Organization: organization, Objects: objects}
	wait, cancel := context.WithTimeout(ctx, recordTimeout)
	receipt, err := recorder.RecordAccess(wait, record)
	cancel()
	if err != nil || !receipt.Known {
		return errors.Join(ErrAuthorityUnavailable, err)
	}
	state := RevocationPending
	if confirmable(kind, receipt) {
		state = RevocationConfirmed
	}
	encoded, err := json.Marshal(objects)
	if err != nil {
		return err
	}
	v := AccessRevocation{ID: record.ID, Kind: kind, State: state}
	err = r.tx.QueryRow(ctx, `INSERT INTO access_revocations(id,tenant_id,organization_id,kind,objects,epoch,seq,state,confirmed_at)
        VALUES($1,nullif($2,''),nullif($3,''),$4,$5,$6,$7,$8,CASE WHEN $8='confirmed' THEN clock_timestamp() END)
        RETURNING recorded_at,confirmed_at`, record.ID, r.reader, organization, kind, encoded, int64(receipt.Epoch), int64(receipt.Seq), state).
		Scan(&v.RecordedAt, &v.ConfirmedAt)
	if err != nil {
		return err
	}
	r.list = append(r.list, v)
	return nil
}

// body adds the revocations to a response body, a JSON object, as its last
// member "revocations". Without any, it is the body itself.
func (r *revocations) body(value any) (any, error) {
	if len(r.list) == 0 {
		return value, nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return spliceRevocations(b, r.list)
}

const revocationsMember = `,"revocations":`

// spliceRevocations adds list to b, a JSON object with members, as its last
// member: the receipt keeps the body, and a replay finds the list there.
func spliceRevocations(b []byte, list []AccessRevocation) (json.RawMessage, error) {
	if len(b) < 3 || b[0] != '{' || b[len(b)-1] != '}' {
		return nil, errors.New("a revocation's answer is not a JSON object with members")
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		return nil, err
	}
	out := append(append([]byte{}, b[:len(b)-1]...), revocationsMember...)
	out = append(out, encoded...)
	return append(out, '}'), nil
}

// currentRevocations brings the states of a stored answer's revocations up
// to date: a replayed answer says what holds now, not what held when it was
// first given.
func currentRevocations(ctx context.Context, tx pgx.Tx, body []byte) ([]byte, error) {
	at := bytes.LastIndex(body, []byte(revocationsMember))
	if at < 0 || len(body) < 2 || body[len(body)-1] != '}' {
		return body, nil
	}
	var list []AccessRevocation
	if err := json.Unmarshal(body[at+len(revocationsMember):len(body)-1], &list); err != nil {
		return body, nil // a member of another kind that happens to share the name
	}
	for i := range list {
		if err := tx.QueryRow(ctx, `SELECT state,confirmed_at FROM access_revocations WHERE id=$1`, list[i].ID).Scan(&list[i].State, &list[i].ConfirmedAt); err != nil {
			return nil, err
		}
	}
	return spliceRevocations(append(append([]byte{}, body[:at]...), '}'), list)
}

// ConfirmAccessRevocations asks the authority service about the pending
// revocations, oldest first, at most limit of them, and confirms those the
// API may confirm now. It stops at the first question the service does not
// answer. It returns how many it confirmed.
func (s *Store) ConfirmAccessRevocations(ctx context.Context, limit int) (int, error) {
	recorder := s.recorder()
	if recorder == nil || limit < 1 {
		return 0, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id,kind FROM access_revocations WHERE state='pending' ORDER BY recorded_at,id LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	type pending struct{ id, kind string }
	var list []pending
	for rows.Next() {
		var p pending
		if err = rows.Scan(&p.id, &p.kind); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, p)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	confirmed := 0
	for _, p := range list {
		ok, err := s.confirm(ctx, recorder, p.id, p.kind)
		if err != nil {
			return confirmed, err
		}
		if ok {
			confirmed++
		}
	}
	return confirmed, nil
}

// progressTimeout bounds one question to the authority service: while the
// standby lags before degraded mode, the service's answer waits for it.
const progressTimeout = 2 * time.Second

func (s *Store) confirm(ctx context.Context, recorder AccessRecorder, id, kind string) (bool, error) {
	ask, cancel := context.WithTimeout(ctx, progressTimeout)
	receipt, err := recorder.AccessProgress(ask, id)
	cancel()
	if err != nil || !confirmable(kind, receipt) {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE access_revocations SET state='confirmed',confirmed_at=clock_timestamp() WHERE id=$1 AND state='pending'`, id)
	return err == nil && tag.RowsAffected() == 1, err
}

// PendingAccessRevocations counts the pending revocations, and gives the
// time of the oldest one (zero when none).
func (s *Store) PendingAccessRevocations(ctx context.Context) (int64, time.Time, error) {
	var count int64
	var oldest *time.Time
	err := s.pool.QueryRow(ctx, `SELECT count(*),min(recorded_at) FROM access_revocations WHERE state='pending'`).Scan(&count, &oldest)
	if err != nil || oldest == nil {
		return count, time.Time{}, err
	}
	return count, *oldest, nil
}

// AccessRevocation reads one revocation: an organization's, for those who
// read its audit trail, or the platform's own, for the platform operator. A
// pending one is first asked about again. Any other is not found.
func (a *Accounts) AccessRevocation(ctx context.Context, p Principal, id string) (AccessRevocation, error) {
	if !authoritylog.ValidID(id, "arv_") {
		return AccessRevocation{}, ErrNotFound
	}
	read := func() (AccessRevocation, error) {
		tx, err := a.store.begin(ctx)
		if err != nil {
			return AccessRevocation{}, err
		}
		defer rollback(tx)
		where := "tenant_id IS NULL"
		args := []any{id}
		if p.Kind == "platform" {
			if err = authorizePlatform(ctx, tx, p); err != nil {
				return AccessRevocation{}, err
			}
		} else {
			current, err := authorizeTenant(ctx, tx, p, authorization.ScopeAuditRead)
			if err != nil {
				return AccessRevocation{}, err
			}
			if !authorization.CanAdminister(tenantAccess(p), authorization.Role(current.Role), authorization.ReadAudit) {
				return AccessRevocation{}, ErrForbidden
			}
			where, args = "tenant_id=$2", append(args, p.TenantID)
		}
		v := AccessRevocation{ID: id}
		err = tx.QueryRow(ctx, `SELECT kind,state,recorded_at,confirmed_at FROM access_revocations WHERE id=$1 AND `+where, args...).
			Scan(&v.Kind, &v.State, &v.RecordedAt, &v.ConfirmedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return v, ErrNotFound
		}
		if err != nil {
			return v, err
		}
		return v, commit(ctx, tx)
	}
	v, err := read()
	if err != nil || v.State != RevocationPending {
		return v, err
	}
	recorder := a.store.recorder()
	if recorder == nil {
		return v, nil
	}
	if ok, err := a.store.confirm(ctx, recorder, id, v.Kind); err != nil || !ok {
		return v, nil // still pending; the service may not answer now
	}
	return read()
}

// collect reads the IDs a statement returns.
func collect(rows pgx.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// objects names objects of one part each.
func objects(ids []string) [][]string {
	out := make([][]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, []string{id})
	}
	return out
}
