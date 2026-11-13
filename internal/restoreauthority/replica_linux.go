//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/mattn/go-sqlite3"
)

// The replica of both authorities, on the standby (ADR 005, option a). It is
// one SQLite file, replica.sqlite, in a private directory: the catalogue's
// tables, with the signing secret zeroed and kept wrapped to the unlock key,
// and one row per volume, with its key wrapped. It applies records in order,
// each in one transaction, and refuses a gap, an older or newer epoch, and a
// duplicate whose content differs. It is never opened as an authority: Open
// and keyauthority.Open do not find their files in it, and only Promote turns
// it into authorities. It never holds an unwrapped secret.

const replicaSchema = `
CREATE TABLE replica_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 restore_identity TEXT NOT NULL, key_identity TEXT NOT NULL,
 epoch INTEGER NOT NULL CHECK(epoch>0),
 seq INTEGER NOT NULL CHECK(seq>=0),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 recipient BLOB NOT NULL CHECK(length(recipient)=32),
 wrapped_secret BLOB,
 promoted INTEGER NOT NULL DEFAULT 0 CHECK(promoted IN (0,1))
);
CREATE TABLE replica_window (seq INTEGER PRIMARY KEY NOT NULL CHECK(seq>0), digest BLOB NOT NULL CHECK(length(digest)=32));
CREATE TABLE replica_volumes (
 volume TEXT PRIMARY KEY NOT NULL, agent TEXT NOT NULL,
 allocated INTEGER NOT NULL CHECK(allocated IN (0,1)),
 revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
 commitment BLOB CHECK(commitment IS NULL OR length(commitment)=32),
 wrapped BLOB,
 CHECK((commitment IS NULL) = (wrapped IS NULL)),
 CHECK(revoked=0 OR wrapped IS NULL)
);
PRAGMA user_version=3;
`

// replicaWindow is how many recent digests the replica keeps to recognize a
// resent record. Only digests: the log keeps no key material once applied.
const replicaWindow = 4096

// catalogueTables are copied, in this order, by a snapshot and a promotion.
var catalogueTables = []string{"stores", "reservations", "revocations", "outcomes", "losses", "reruns"}

func sqliteDSN(path string) string {
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	for k, v := range sqliteOptions {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// privateFile checks an existing database file: regular, private, ours.
func privateFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return ErrUnavailable
	}
	return nil
}

func openSQLite(path string) (*sql.DB, error) {
	if err := privateFile(path); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	db, err := sql.Open("sqlite3", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// createReplicaFile creates an empty replica database at path.
func createReplicaFile(ctx context.Context, path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f.Close()
	db, err := openSQLite(path)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, schema+lossSchema+replicaSchema)
	return err
}

// schemaOf lists a database's schema, to compare a snapshot with ours.
func schemaOf(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT type||'|'||name||'|'||tbl_name||'|'||coalesce(sql,'') FROM sqlite_master ORDER BY type,name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err = rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	var v int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return nil, err
	}
	return append(out, "user_version|"+strconv.Itoa(v)), rows.Err()
}

type replicaState struct {
	restore, key string
	epoch, seq   uint64
	digest       []byte
	recipient    []byte
	wrapped      []byte
	promoted     bool
}

func (s replicaState) position() authoritylog.Position {
	return authoritylog.Position{Epoch: s.epoch, Seq: s.seq, Digest: bytes.Clone(s.digest)}
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readReplicaState(ctx context.Context, q querier) (replicaState, error) {
	var s replicaState
	err := q.QueryRowContext(ctx, "SELECT restore_identity,key_identity,epoch,seq,digest,recipient,wrapped_secret,promoted FROM replica_state WHERE singleton=1").
		Scan(&s.restore, &s.key, &s.epoch, &s.seq, &s.digest, &s.recipient, &s.wrapped, &s.promoted)
	if err != nil || !validID(s.restore, "restoreauth_") || !validID(s.key, "keyauth_") || len(s.digest) != 32 || len(s.recipient) != 32 {
		return s, errors.Join(ErrUnavailable, err)
	}
	return s, nil
}

// Replica is the standby's copy of both authorities. It implements
// authoritylog.Link, so the primary can talk to it in memory or over TLS.
type Replica struct {
	db      *sql.DB
	path    string
	lock    chan struct{}
	hook    func(string) // tests interrupt the actual transaction boundary
	metrics atomic.Pointer[authoritylog.ReplicaMetrics]
}

var _ authoritylog.Link = (*Replica)(nil)

// InitializeReplica creates the replica in root, a new private directory,
// from a snapshot written by Catalog.Snapshot. It checks the snapshot's schema
// and state, and never replaces an existing replica.
func InitializeReplica(ctx context.Context, root, snapshot string) (*Replica, error) {
	abs, err := directory(root, true)
	if err != nil {
		return nil, err
	}
	final := filepath.Join(abs, "replica.sqlite")
	if _, err = os.Lstat(final); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, ErrConflict
	}
	src, err := os.OpenFile(snapshot, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	if st, err := src.Stat(); err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, ErrInput
	}
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	temp := filepath.Join(abs, ".replica-"+hex.EncodeToString(nonce[:])+".sqlite")
	dst, err := os.OpenFile(temp, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(temp)
	_, err = io.Copy(dst, src)
	if err == nil {
		err = dst.Sync()
	}
	if e := dst.Close(); err == nil {
		err = e
	}
	if err != nil {
		return nil, err
	}
	if err = checkSnapshot(ctx, temp); err != nil {
		return nil, err
	}
	if err = os.Link(temp, final); err != nil {
		return nil, err
	}
	if err = syncDir(abs); err != nil {
		return nil, err
	}
	if err = syncDir(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	db, err := openSQLite(final)
	if err != nil {
		return nil, err
	}
	return &Replica{db: db, path: final, lock: make(chan struct{}, 1)}, nil
}

func checkSnapshot(ctx context.Context, path string) error {
	db, err := openSQLite(path)
	if err != nil {
		return err
	}
	defer db.Close()
	var ok string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&ok); err != nil || ok != "ok" {
		return errors.Join(ErrInput, err)
	}
	got, err := schemaOf(ctx, db)
	if err != nil {
		return errors.Join(ErrInput, err)
	}
	reference, err := sql.Open("sqlite3", "file::memory:?mode=memory")
	if err != nil {
		return err
	}
	defer reference.Close()
	reference.SetMaxOpenConns(1)
	if _, err = reference.ExecContext(ctx, schema+lossSchema+replicaSchema); err != nil {
		return err
	}
	want, err := schemaOf(ctx, reference)
	if err != nil {
		return err
	}
	if !slices.Equal(got, want) {
		return ErrInput
	}
	s, err := readReplicaState(ctx, db)
	if err != nil || s.promoted || s.epoch == 0 || len(s.wrapped) == 0 {
		return errors.Join(ErrInput, err)
	}
	var identity, keyIdentity string
	var secret []byte
	if err = db.QueryRowContext(ctx, "SELECT identity,key_identity,secret FROM authority WHERE singleton=1").Scan(&identity, &keyIdentity, &secret); err != nil ||
		identity != s.restore || keyIdentity != s.key || !bytes.Equal(secret, make([]byte, 32)) {
		return errors.Join(ErrInput, err)
	}
	if s.seq > 0 {
		var digest []byte
		if err = db.QueryRowContext(ctx, "SELECT digest FROM replica_window WHERE seq=?", s.seq).Scan(&digest); err != nil || !bytes.Equal(digest, s.digest) {
			return errors.Join(ErrInput, err)
		}
	}
	var foreign int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM pragma_foreign_key_check").Scan(&foreign); err != nil || foreign != 0 {
		return errors.Join(ErrInput, err)
	}
	return nil
}

// OpenReplica opens the replica in root. Both identities are required and
// must be those the replica was created for.
func OpenReplica(ctx context.Context, root, restoreIdentity, keyIdentity string) (*Replica, error) {
	if !validID(restoreIdentity, "restoreauth_") || !validID(keyIdentity, "keyauth_") {
		return nil, ErrInput
	}
	r, s, err := openReplica(ctx, root)
	if err != nil {
		return nil, err
	}
	if s.restore != restoreIdentity || s.key != keyIdentity {
		r.Close()
		return nil, ErrUnavailable
	}
	return r, nil
}

func openReplica(ctx context.Context, root string) (*Replica, replicaState, error) {
	abs, err := directory(root, false)
	if err != nil {
		return nil, replicaState{}, err
	}
	path := filepath.Join(abs, "replica.sqlite")
	db, err := openSQLite(path)
	if err != nil {
		return nil, replicaState{}, err
	}
	s, err := readReplicaState(ctx, db)
	if err != nil {
		db.Close()
		return nil, s, err
	}
	return &Replica{db: db, path: path, lock: make(chan struct{}, 1)}, s, nil
}

// Close closes the replica.
func (r *Replica) Close() error { return r.db.Close() }

// Observe sends the replica's metrics to m.
func (r *Replica) Observe(m *authoritylog.ReplicaMetrics) { r.metrics.Store(m) }

// Position returns how far the replica has applied the stream.
func (r *Replica) Position(ctx context.Context) (authoritylog.Position, error) {
	s, err := readReplicaState(ctx, r.db)
	return s.position(), err
}

func refuse(kind string, s replicaState) error {
	return &authoritylog.Refusal{Kind: kind, Position: s.position()}
}

// Sync applies the request's records in order, then returns the replica's
// position. A refusal leaves every record before the refused one applied.
func (r *Replica) Sync(ctx context.Context, req authoritylog.Request) (authoritylog.Position, error) {
	select {
	case r.lock <- struct{}{}:
	case <-ctx.Done():
		return authoritylog.Position{}, ctx.Err()
	}
	defer func() { <-r.lock }()
	s, err := readReplicaState(ctx, r.db)
	if err != nil {
		return authoritylog.Position{}, r.refused(refuse(authoritylog.RefusedUnavailable, s))
	}
	switch {
	case req.RestoreAuthority != s.restore || req.KeyAuthority != s.key:
		return s.position(), r.refused(refuse(authoritylog.RefusedIdentity, s))
	case s.promoted:
		return s.position(), r.refused(refuse(authoritylog.RefusedPromoted, s))
	case req.Epoch < s.epoch:
		return s.position(), r.refused(refuse(authoritylog.RefusedOlderEpoch, s))
	case req.Epoch > s.epoch:
		return s.position(), r.refused(refuse(authoritylog.RefusedNewerEpoch, s))
	case len(req.Records) > authoritylog.MaxRecords:
		return s.position(), r.refused(refuse(authoritylog.RefusedInvalid, s))
	}
	applied := false
	for _, raw := range req.Records {
		next, err := r.apply(ctx, raw, s)
		if err != nil {
			var refusal *authoritylog.Refusal
			if !errors.As(err, &refusal) {
				err = refuse(authoritylog.RefusedUnavailable, s)
			}
			return s.position(), r.refused(err)
		}
		applied = applied || next.seq != s.seq
		s = next
	}
	r.metrics.Load().Position(s.position(), applied)
	return s.position(), nil
}

func (r *Replica) refused(err error) error {
	var refusal *authoritylog.Refusal
	if errors.As(err, &refusal) {
		r.metrics.Load().Refused(refusal.Kind)
	}
	return err
}

func (r *Replica) apply(ctx context.Context, raw []byte, s replicaState) (replicaState, error) {
	rec, err := authoritylog.Decode(raw)
	if err != nil {
		return s, refuse(authoritylog.RefusedInvalid, s)
	}
	switch {
	case rec.Epoch < s.epoch:
		return s, refuse(authoritylog.RefusedOlderEpoch, s)
	case rec.Epoch > s.epoch:
		return s, refuse(authoritylog.RefusedNewerEpoch, s)
	}
	digest := authoritylog.Digest(raw)
	if rec.Seq <= s.seq {
		// A resent record: acknowledge it only if it is the one applied.
		var got []byte
		err := r.db.QueryRowContext(ctx, "SELECT digest FROM replica_window WHERE seq=?", rec.Seq).Scan(&got)
		if err == nil && bytes.Equal(got, digest) {
			return s, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return s, err
		}
		return s, refuse(authoritylog.RefusedConflict, s)
	}
	if rec.Seq > s.seq+1 {
		return s, refuse(authoritylog.RefusedGap, s)
	}
	if !bytes.Equal(rec.Prev, s.digest) {
		return s, refuse(authoritylog.RefusedConflict, s)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return s, err
	}
	defer tx.Rollback()
	for _, op := range rec.Ops {
		if err = r.applyOp(ctx, tx, op); err != nil {
			if errors.Is(err, ErrConflict) {
				return s, refuse(authoritylog.RefusedConflict, s)
			}
			return s, err
		}
	}
	// promoted=0 here, in the transaction: a promotion that committed after
	// the state was read wins over this record.
	result, err := tx.ExecContext(ctx, "UPDATE replica_state SET seq=?,digest=? WHERE singleton=1 AND seq=? AND epoch=? AND promoted=0", rec.Seq, digest, s.seq, s.epoch)
	if err != nil {
		return s, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return s, refuse(authoritylog.RefusedPromoted, s)
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO replica_window VALUES(?,?)", rec.Seq, digest); err != nil {
		return s, err
	}
	if rec.Seq > replicaWindow {
		if _, err = tx.ExecContext(ctx, "DELETE FROM replica_window WHERE seq<=?", rec.Seq-replicaWindow); err != nil {
			return s, err
		}
	}
	if r.hook != nil {
		r.hook("replica_before_commit")
	}
	if err = tx.Commit(); err != nil {
		return s, err
	}
	if r.hook != nil {
		r.hook("replica_after_commit")
	}
	s.seq, s.digest = rec.Seq, digest
	return s, nil
}

// applyOp replays one operation. A statement must change exactly the rows it
// changed on the primary; anything else means the histories differ.
func (r *Replica) applyOp(ctx context.Context, tx *sql.Tx, op authoritylog.Op) error {
	switch op.Kind {
	case authoritylog.OpStatement:
		text, ok := statements[statement(op.Statement)]
		if !ok {
			return ErrConflict
		}
		args := make([]any, len(op.Args))
		for i, a := range op.Args {
			args[i] = a.Value()
		}
		result, err := tx.ExecContext(ctx, text, args...)
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && (sqliteErr.Code == sqlite3.ErrConstraint || sqliteErr.Code == sqlite3.ErrRange || sqliteErr.Code == sqlite3.ErrMismatch) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != op.Rows {
			return ErrConflict
		}
		return nil
	case authoritylog.OpKeyCreate, authoritylog.OpKeyRevoke:
		var agent string
		var revoked bool
		var commitment []byte
		err := tx.QueryRowContext(ctx, "SELECT agent,revoked,commitment FROM replica_volumes WHERE volume=?", op.Volume).Scan(&agent, &revoked, &commitment)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if exists && agent != op.Agent {
			return ErrConflict
		}
		if op.Kind == authoritylog.OpKeyRevoke {
			// The tombstone and the removal of the wrapped copy are one write.
			if exists {
				_, err = tx.ExecContext(ctx, "UPDATE replica_volumes SET revoked=1,commitment=NULL,wrapped=NULL WHERE volume=?", op.Volume)
			} else {
				_, err = tx.ExecContext(ctx, "INSERT INTO replica_volumes VALUES(?,?,0,1,NULL,NULL)", op.Volume, op.Agent)
			}
			return err
		}
		switch {
		case !exists:
			_, err = tx.ExecContext(ctx, "INSERT INTO replica_volumes VALUES(?,?,1,0,?,?)", op.Volume, op.Agent, op.Commitment, op.Wrapped)
			return err
		case revoked:
			return nil // a destroyed key never comes back
		case bytes.Equal(commitment, op.Commitment):
			return nil // the same key, recorded again after a crash
		}
		return ErrConflict // never a second key for a volume
	}
	return ErrConflict
}

// replicaRoots refuses roots that overlap one another.
func replicaRoots(roots ...string) error {
	for i := range roots {
		for j := range roots {
			if i != j && CheckSeparation(roots[i], roots[j]) != nil {
				return ErrInput
			}
		}
	}
	return nil
}

func validRootPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}
