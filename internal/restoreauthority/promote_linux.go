//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// Promotion is the result of Promote.
type Promotion struct {
	// The identities stay those of the replicated authorities, so archives
	// and their manifests stay valid on the standby.
	RestoreAuthority, KeyAuthority string
	// Epoch is the new primary's epoch. The old primary's records carry an
	// older one, and any replica built from the new primary refuses them.
	Epoch uint64
	// Position is the last record the replica applied.
	Position authoritylog.Position
}

type replicaVolume struct {
	keyauthority.Entry
	commitment, wrapped []byte
}

func (r *Replica) volumes(ctx context.Context) ([]replicaVolume, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT volume,agent,allocated,revoked,commitment,wrapped FROM replica_volumes ORDER BY volume")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []replicaVolume
	for rows.Next() {
		var v replicaVolume
		if err = rows.Scan(&v.Volume, &v.Agent, &v.Allocated, &v.Revoked, &v.commitment, &v.wrapped); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// unwrap opens the replica's secret and keys with the unlock key, and checks
// each key against its commitment. The caller clears the result.
func unwrap(ctx context.Context, r *Replica, s replicaState, unlock *authoritylog.UnlockKey) ([]byte, []keyauthority.Entry, error) {
	secret, err := unlock.Open(authoritylog.SecretContext(s.restore), s.wrapped)
	if err != nil || len(secret) != 32 {
		clear(secret)
		return nil, nil, errors.Join(ErrInput, err)
	}
	volumes, err := r.volumes(ctx)
	if err != nil {
		clear(secret)
		return nil, nil, errors.Join(ErrUnavailable, err)
	}
	entries := make([]keyauthority.Entry, 0, len(volumes))
	fail := func(err error) ([]byte, []keyauthority.Entry, error) {
		clear(secret)
		for _, e := range entries {
			clear(e.Key)
		}
		return nil, nil, err
	}
	for _, v := range volumes {
		e := v.Entry
		if v.wrapped != nil {
			key, err := unlock.Open(authoritylog.KeyContext(s.key, v.Agent, v.Volume), v.wrapped)
			if err != nil || len(key) != 32 || !bytes.Equal(authoritylog.KeyCommitment(s.key, v.Agent, v.Volume, key), v.commitment) {
				clear(key)
				return fail(errors.Join(ErrInput, err))
			}
			e.Key = key
		}
		entries = append(entries, e)
	}
	return secret, entries, nil
}

// Promote turns the replica in replicaRoot into the two authorities of a new
// primary: a key authority in keyRoot and a restore authority in restoreRoot,
// both new directories, with the replicated identities. It needs the
// operator's unlock key. It first checks that every wrapped secret opens;
// then it marks the replica promoted, so that it refuses every later record;
// then it writes both authorities; last, it deletes the replica's wrapped
// copies. The new primary is standalone, with the next epoch, until a new
// snapshot arms it for a new standby. A repeated call completes an
// interrupted one.
//
// The administrative command around it comes in a later wave; fencing the
// old primary stays the operator's first step (docs/recovery.md).
func Promote(ctx context.Context, replicaRoot, restoreRoot, keyRoot string, unlock *authoritylog.UnlockKey) (Promotion, error) {
	var p Promotion
	if unlock == nil || !validRootPath(replicaRoot) || !validRootPath(restoreRoot) || !validRootPath(keyRoot) {
		return p, ErrInput
	}
	if err := replicaRoots(replicaRoot, restoreRoot, keyRoot); err != nil {
		return p, err
	}
	r, s, err := openReplica(ctx, replicaRoot)
	if err != nil {
		return p, err
	}
	defer r.Close()
	select {
	case r.lock <- struct{}{}:
	case <-ctx.Done():
		return p, ctx.Err()
	}
	defer func() { <-r.lock }()
	recipient := unlock.Recipient()
	if !bytes.Equal(recipient[:], s.recipient) {
		return p, errors.Join(ErrInput, authoritylog.ErrWrap)
	}
	p = Promotion{RestoreAuthority: s.restore, KeyAuthority: s.key, Epoch: s.epoch + 1, Position: s.position()}
	if s.promoted && s.wrapped == nil {
		// Done before: check what it produced.
		return p, checkPromoted(ctx, restoreRoot, keyRoot, p)
	}
	secret, entries, err := unwrap(ctx, r, s, unlock)
	if err != nil {
		return p, err
	}
	defer func() {
		clear(secret)
		for _, e := range entries {
			clear(e.Key)
		}
	}()
	if !s.promoted {
		result, err := r.db.ExecContext(ctx, "UPDATE replica_state SET promoted=1 WHERE singleton=1 AND promoted=0 AND seq=?", s.seq)
		if err != nil {
			return p, err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return p, errors.Join(ErrConflict, err) // a record arrived meanwhile: promote again
		}
	}
	if _, err = keyauthority.Install(ctx, keyRoot, s.key, entries); err != nil {
		return p, err
	}
	if err = installPromoted(ctx, restoreRoot, r.path, secret, p); err != nil {
		return p, err
	}
	// No wrapped copy outlives the promotion: the unlock key was given.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE replica_volumes SET commitment=NULL,wrapped=NULL WHERE wrapped IS NOT NULL"); err != nil {
		return p, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE replica_state SET wrapped_secret=NULL WHERE singleton=1"); err != nil {
		return p, err
	}
	return p, tx.Commit()
}

func checkPromoted(ctx context.Context, restoreRoot, keyRoot string, p Promotion) error {
	if _, err := keyauthority.Open(keyRoot, p.KeyAuthority); err != nil {
		return err
	}
	return checkCatalogue(ctx, restoreRoot, p)
}

func checkCatalogue(ctx context.Context, restoreRoot string, p Promotion) error {
	c, err := Open(ctx, restoreRoot, p.RestoreAuthority, p.KeyAuthority)
	if err != nil {
		return err
	}
	defer c.Close()
	s, err := c.Replication(ctx)
	if err != nil {
		return err
	}
	if s.Committed.Epoch != p.Epoch || s.Committed.Seq != p.Position.Seq {
		return ErrConflict
	}
	return nil
}

// installPromoted writes the restore authority of a promoted standby.
func installPromoted(ctx context.Context, root, replicaPath string, secret []byte, p Promotion) error {
	abs, err := directory(root, true)
	if err != nil {
		return err
	}
	identity, err := readIdentity(abs)
	if err == nil {
		if identity != p.RestoreAuthority {
			return ErrConflict
		}
		return checkCatalogue(ctx, root, p)
	}
	c, err := openDatabase(abs, true)
	if err != nil {
		return err
	}
	defer c.Close()
	c.identity, c.keyIdentity = p.RestoreAuthority, p.KeyAuthority
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
	}()
	var tables int
	if err = conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		if err = copyPromoted(ctx, conn, replicaPath, secret, p); err != nil {
			return err
		}
	}
	// Committed before, or now: check it, then publish the identity.
	var gotIdentity, gotKey string
	var epoch, seq uint64
	if err = conn.QueryRowContext(ctx, "SELECT a.identity,a.key_identity,r.epoch,r.seq FROM authority a, replication r").Scan(&gotIdentity, &gotKey, &epoch, &seq); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if gotIdentity != p.RestoreAuthority || gotKey != p.KeyAuthority || epoch != p.Epoch || seq != p.Position.Seq {
		return ErrConflict
	}
	if err = c.publishIdentity(); err != nil {
		return err
	}
	return syncDir(filepath.Dir(abs))
}

func copyPromoted(ctx context.Context, conn *sql.Conn, replicaPath string, secret []byte, p Promotion) error {
	if _, err := conn.ExecContext(ctx, "ATTACH DATABASE ? AS replica", replicaPath); err != nil {
		return err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "DETACH DATABASE replica")
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, schema+lossSchema+replicationSchema); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO main.authority SELECT singleton,identity,key_identity,?,revision FROM replica.authority", secret); err != nil {
		return err
	}
	for _, table := range catalogueTables {
		// table is from a fixed list, never from input.
		if _, err = tx.ExecContext(ctx, "INSERT INTO main."+table+" SELECT * FROM replica."+table); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO main.replication VALUES(1,?,NULL,?,?)", p.Epoch, p.Position.Seq, p.Position.Digest); err != nil {
		return err
	}
	return tx.Commit()
}
