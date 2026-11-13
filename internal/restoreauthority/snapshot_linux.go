//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// Snapshot arms both authorities for a replica and writes the replica's
// initial state to path, a new file. The file holds the catalogue's tables
// with the signing secret zeroed, the secret and every live volume key
// wrapped to recipient, the tombstones, and the stream's position. It holds
// no secret in clear. It is consistent: it runs in one catalogue transaction,
// which every replicated write of either authority takes too.
//
// Arming is permanent. From then on, a process without the replica refuses
// every operation (ErrReplicaRequired, and keyauthority's armed check). The
// first snapshot must be taken with the worker stopped: a worker started
// before it writes keys without the journal. A later snapshot, to build a new
// replica, may run beside a worker that replicates; it keeps the epoch, and
// the recipient must stay the same.
func (c *Catalog) Snapshot(ctx context.Context, keys *keyauthority.Files, recipient authoritylog.Recipient, path string) (authoritylog.Position, error) {
	var position authoritylog.Position
	if keys == nil || keys.Identity() != c.keyIdentity || !validRootPath(path) {
		return position, ErrInput
	}
	if _, err := authoritylog.ParseRecipient(recipient.String()); err != nil {
		return position, ErrInput
	}
	if err := CheckSeparation(c.root, path); err != nil {
		return position, err
	}
	// Arm nothing on a catalogue that cannot hold the stream.
	if err := c.run(ctx, false, func(tx *sql.Tx) error {
		v, err := version(ctx, tx)
		if err == nil && v < 3 {
			err = ErrUnavailable // upgrade with Initialize first
		}
		return err
	}); err != nil {
		return position, err
	}
	if err := createReplicaFile(ctx, path); err != nil {
		return position, err
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(path)
		}
	}()
	if err := keys.MarkReplicated(); err != nil {
		return position, err
	}
	if err := c.checkFile(); err != nil {
		return position, err
	}
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return position, errors.Join(ErrUnavailable, err)
	}
	// The attached file must not stay on the pool's connection.
	defer func() {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
	}()
	if _, err = conn.ExecContext(ctx, "ATTACH DATABASE ? AS snap", path); err != nil {
		return position, errors.Join(ErrUnavailable, err)
	}
	if _, err = conn.ExecContext(ctx, "PRAGMA snap.journal_mode=DELETE; PRAGMA snap.synchronous=FULL; PRAGMA snap.secure_delete=ON"); err != nil {
		return position, errors.Join(ErrUnavailable, err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return position, errors.Join(ErrUnavailable, err)
	}
	defer tx.Rollback()
	if position, err = c.snapshot(ctx, tx, keys, recipient); err != nil {
		return position, err
	}
	if err = c.checkFile(); err != nil {
		return position, err
	}
	if err = tx.Commit(); err != nil {
		return position, err
	}
	if _, err = conn.ExecContext(ctx, "DETACH DATABASE snap"); err != nil {
		return position, err
	}
	if err = syncDir(filepath.Dir(path)); err != nil {
		return position, err
	}
	ok = true
	return position, nil
}

func (c *Catalog) snapshot(ctx context.Context, tx *sql.Tx, keys *keyauthority.Files, recipient authoritylog.Recipient) (authoritylog.Position, error) {
	var position authoritylog.Position
	var identity, keyIdentity string
	var secret []byte
	if err := tx.QueryRowContext(ctx, "SELECT identity,key_identity,secret FROM main.authority WHERE singleton=1").Scan(&identity, &keyIdentity, &secret); err != nil {
		return position, errors.Join(ErrUnavailable, err)
	}
	defer clear(secret)
	if identity != c.identity || keyIdentity != c.keyIdentity || len(secret) != 32 {
		return position, ErrUnavailable
	}
	if v, err := version(ctx, tx); err != nil || v < 3 {
		return position, errors.Join(ErrUnavailable, err) // upgrade with Initialize first
	}
	state, err := readReplication(ctx, tx)
	if err != nil {
		return position, err
	}
	switch {
	case state == nil:
		_, err = tx.ExecContext(ctx, "INSERT INTO main.replication VALUES(1,1,?,0,?)", recipient[:], authoritylog.Origin())
	case state.recipient == nil:
		_, err = tx.ExecContext(ctx, "UPDATE main.replication SET recipient=? WHERE singleton=1", recipient[:])
	case !bytes.Equal(state.recipient, recipient[:]):
		return position, ErrConflict
	}
	if err != nil {
		return position, err
	}
	if state, err = readReplication(ctx, tx); err != nil || !state.armed() {
		return position, errors.Join(ErrUnavailable, err)
	}
	position = authoritylog.Position{Epoch: state.epoch, Seq: state.seq, Digest: state.digest}
	if _, err = tx.ExecContext(ctx, "INSERT INTO snap.authority SELECT singleton,identity,key_identity,zeroblob(32),revision FROM main.authority"); err != nil {
		return position, err
	}
	for _, table := range catalogueTables {
		// table is from a fixed list, never from input.
		if _, err = tx.ExecContext(ctx, "INSERT INTO snap."+table+" SELECT * FROM main."+table); err != nil {
			return position, err
		}
	}
	wrapped, err := authoritylog.Seal(recipient, authoritylog.SecretContext(identity), secret)
	if err != nil {
		return position, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO snap.replica_state VALUES(1,?,?,?,?,?,?,?,0)",
		identity, keyIdentity, state.epoch, state.seq, state.digest, recipient[:], wrapped); err != nil {
		return position, err
	}
	if state.seq > 0 {
		if _, err = tx.ExecContext(ctx, "INSERT INTO snap.replica_window VALUES(?,?)", state.seq, state.digest); err != nil {
			return position, err
		}
	}
	// Under the catalogue's write lock: no journaled key write runs now.
	err = keys.Export(ctx, func(e keyauthority.Entry) error {
		var commitment, wrapped []byte
		if e.Key != nil && !e.Revoked {
			commitment = authoritylog.KeyCommitment(keyIdentity, e.Agent, e.Volume, e.Key)
			var err error
			if wrapped, err = authoritylog.Seal(recipient, authoritylog.KeyContext(keyIdentity, e.Agent, e.Volume), e.Key); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO snap.replica_volumes VALUES(?,?,?,?,?,?)",
			e.Volume, e.Agent, e.Allocated || commitment != nil, e.Revoked, commitment, wrapped)
		return err
	})
	return position, err
}
