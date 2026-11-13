//go:build linux && cgo

// Package restoreauthority persists the independent root of restore_authority.qnt.
// Its directory must be excluded from control-plane and guest backup restoration.
// A pinned identity detects replacement, not rollback of that same authority.
// This catalogue does not retire VMs, authenticate guest replies, reconstruct
// application data, or attest destruction of cached/external encryption keys.
package restoreauthority

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrInput       = errors.New("invalid authority input")
	ErrUnavailable = errors.New("independent authority unavailable or inconsistent")
	ErrConflict    = errors.New("immutable authority binding conflict")
	ErrStale       = errors.New("obsolete incarnation or catalogue receipt")
	ErrRevoked     = errors.New("subject key access revoked")
	ErrSealed      = errors.New("store permanently sealed")
	ErrHistory     = errors.New("acknowledged outcome history is incomplete")
	ErrNotDeclared = errors.New("no loss declared for this outcome and incarnation")
)

type Catalog struct {
	db             *sql.DB
	root, identity string
	keyIdentity    string
	device, inode  uint64
	hook           func(string) // tests interrupt the actual transaction boundary

	// repl is the link to the replica; nil in standalone mode.
	repl      *replicator
	recMu     sync.Mutex
	recording map[*sql.Tx]*txRecord
}

type Binding struct {
	Store, Volume string
	Incarnation   uint64
}

// Receipt is an authority snapshot, later acknowledged by a trusted worker only
// after authenticated durable guest fencing. MAC is not a guest fence proof.
type Receipt struct {
	Authority   string
	Store       string
	Incarnation uint64
	Revision    uint64
	Subjects    []string
	MAC         []byte
}

// Outcome identifies real committed data; the digest is NOT recovery data.
type Outcome struct {
	ID     string
	Digest [32]byte
}

const schema = `
CREATE TABLE authority (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 identity TEXT NOT NULL, key_identity TEXT NOT NULL,
 secret BLOB NOT NULL CHECK(length(secret)=32),
 revision INTEGER NOT NULL CHECK(revision>=0)
);
CREATE TABLE stores (
 id TEXT PRIMARY KEY NOT NULL, volume TEXT UNIQUE NOT NULL,
 incarnation INTEGER NOT NULL CHECK(incarnation>0), sealed INTEGER NOT NULL DEFAULT 0 CHECK(sealed IN (0,1)),
 ack_revision INTEGER NOT NULL DEFAULT -1 CHECK(ack_revision>=-1)
);
CREATE TABLE reservations (
 operation TEXT PRIMARY KEY NOT NULL, store TEXT NOT NULL REFERENCES stores(id),
 previous INTEGER NOT NULL CHECK(previous>0), current INTEGER NOT NULL CHECK(current=previous+1)
);
CREATE TABLE revocations (subject TEXT PRIMARY KEY NOT NULL, revision INTEGER UNIQUE NOT NULL CHECK(revision>0));
CREATE TABLE outcomes (
 id TEXT PRIMARY KEY NOT NULL, store TEXT NOT NULL REFERENCES stores(id),
 digest BLOB NOT NULL CHECK(length(digest)=32)
);
CREATE INDEX outcomes_by_store ON outcomes(store);
`

// The schema version is SQLite's user_version. Version 1, the schema above,
// did not record it (user_version 0). Initialize upgrades an older catalogue;
// Open never changes the schema. An unknown version fails closed. Version 3
// adds the replication stream (replication_linux.go); a version 2 catalogue
// keeps working in standalone mode.
const schemaVersion = 3

// lossSchema is version 2: the declared losses and reruns of D-03 option B
// (docs/adr/003-restore-rpo.md). Triggers refuse any update or delete, so a
// declared loss and a recorded rerun are never withdrawn.
const lossSchema = `
CREATE UNIQUE INDEX outcomes_by_identity ON outcomes(id,store);
CREATE TABLE losses (
 outcome TEXT NOT NULL, store TEXT NOT NULL, incarnation INTEGER NOT NULL CHECK(incarnation>1),
 PRIMARY KEY(outcome,incarnation), FOREIGN KEY(outcome,store) REFERENCES outcomes(id,store)
);
CREATE INDEX losses_by_store ON losses(store,incarnation);
CREATE TABLE reruns (
 outcome TEXT NOT NULL, incarnation INTEGER NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32),
 PRIMARY KEY(outcome,incarnation), FOREIGN KEY(outcome,incarnation) REFERENCES losses(outcome,incarnation)
);
CREATE TRIGGER losses_never_updated BEFORE UPDATE ON losses BEGIN SELECT RAISE(ABORT,'declared loss is permanent'); END;
CREATE TRIGGER losses_never_deleted BEFORE DELETE ON losses BEGIN SELECT RAISE(ABORT,'declared loss is permanent'); END;
CREATE TRIGGER reruns_never_updated BEFORE UPDATE ON reruns BEGIN SELECT RAISE(ABORT,'rerun record is permanent'); END;
CREATE TRIGGER reruns_never_deleted BEFORE DELETE ON reruns BEGIN SELECT RAISE(ABORT,'rerun record is permanent'); END;
PRAGMA user_version=2;
`

func version(ctx context.Context, tx *sql.Tx) (int, error) {
	var v int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, errors.Join(ErrUnavailable, err)
	}
	switch v {
	case 0:
		return 1, nil
	case 2, schemaVersion:
		return v, nil
	}
	return 0, ErrUnavailable
}

// upgrade only adds empty tables; it never rewrites recorded state.
func upgrade(ctx context.Context, tx *sql.Tx) error {
	v, err := version(ctx, tx)
	if err == nil && v == 1 {
		_, err = tx.ExecContext(ctx, lossSchema)
		v = 2
	}
	if err == nil && v == 2 {
		_, err = tx.ExecContext(ctx, replicationSchema)
	}
	return err
}

// lossesAvailable is false on a version 1 catalogue: no loss can be declared
// there. Operations that need the loss tables fail closed until Initialize
// has upgraded it.
func lossesAvailable(ctx context.Context, tx *sql.Tx) (bool, error) {
	v, err := version(ctx, tx)
	return v >= 2, err
}

func requireLosses(ctx context.Context, tx *sql.Tx) error {
	available, err := lossesAvailable(ctx, tx)
	if err == nil && !available {
		err = ErrUnavailable
	}
	return err
}

func validID(id, prefix string) bool {
	if len(id) != len(prefix)+32 || !strings.HasPrefix(id, prefix) || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id[len(prefix):])
	return err == nil
}

func validName(s string) bool {
	return len(s) > 0 && len(s) <= 512 && !strings.ContainsAny(s, "\x00\r\n")
}

func directory(root string, create bool) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil || root == "" {
		return "", ErrInput
	}
	if create {
		if err = os.MkdirAll(abs, 0700); err != nil {
			return "", err
		}
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil || real != abs {
		return "", ErrUnavailable
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return "", ErrUnavailable
	}
	return abs, nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func readIdentity(root string) (string, error) {
	f, err := os.OpenFile(filepath.Join(root, "identity"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() != int64(len("restoreauth_")+32) || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return "", ErrUnavailable
	}
	b := make([]byte, st.Size())
	if _, err = f.ReadAt(b, 0); err != nil || !validID(string(b), "restoreauth_") {
		return "", ErrUnavailable
	}
	return string(b), nil
}

func (c *Catalog) publishIdentity() error {
	f, err := os.CreateTemp(c.root, ".identity-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.WriteString(c.identity); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), filepath.Join(c.root, "identity")); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	identity, err := readIdentity(c.root)
	if err != nil || identity != c.identity {
		return ErrUnavailable
	}
	return syncDir(c.root)
}

func openDatabase(root string, create bool) (*Catalog, error) {
	abs, err := directory(root, create)
	if err != nil {
		return nil, err
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(filepath.Join(abs, "catalog.sqlite"), flags, 0600)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	st, err := f.Stat()
	f.Close()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, ErrUnavailable
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(abs, "catalog.sqlite")}
	q := u.Query()
	for k, v := range sqliteOptions {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	id := st.Sys().(*syscall.Stat_t)
	return &Catalog{db: db, root: abs, device: uint64(id.Dev), inode: id.Ino, recording: map[*sql.Tx]*txRecord{}}, nil
}

// sqliteOptions are those of every authority database. secure_delete
// overwrites deleted content, such as an acknowledged record's wrapped key.
var sqliteOptions = map[string]string{"mode": "rw", "_journal_mode": "DELETE", "_synchronous": "FULL", "_foreign_keys": "on",
	"_busy_timeout": "5000", "_txlock": "immediate", "_secure_delete": "on"}

// Initialize is an explicit administrative operation. Repetition preserves the
// existing identity and key-authority binding; an existing malformed DB is never
// reset. The identity returned here must be pinned outside the restore domain.
func Initialize(ctx context.Context, root, keyIdentity string) (*Catalog, error) {
	if !validID(keyIdentity, "keyauth_") {
		return nil, ErrInput
	}
	abs, err := directory(root, true)
	if err != nil {
		return nil, err
	}
	identity, identityErr := readIdentity(abs)
	if identityErr != nil && !errors.Is(identityErr, os.ErrNotExist) {
		return nil, identityErr
	}
	if identityErr == nil {
		if _, err = os.Lstat(filepath.Join(abs, "catalog.sqlite")); err != nil {
			return nil, ErrUnavailable
		}
	}
	c, err := openDatabase(abs, true)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var tables int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
		return nil, err
	}
	if tables == 0 {
		if identityErr == nil {
			return nil, ErrUnavailable
		}
		var nonce [16]byte
		var secret [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		if _, err = rand.Read(secret[:]); err != nil {
			return nil, err
		}
		defer clear(secret[:])
		if _, err = tx.ExecContext(ctx, schema+lossSchema); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO authority VALUES(1,?,?,?,0)", "restoreauth_"+hex.EncodeToString(nonce[:]), keyIdentity, secret[:]); err != nil {
			return nil, err
		}
	}
	if err = tx.QueryRowContext(ctx, "SELECT identity,key_identity FROM authority WHERE singleton=1").Scan(&c.identity, &c.keyIdentity); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	if !validID(c.identity, "restoreauth_") || c.keyIdentity != keyIdentity {
		return nil, ErrConflict
	}
	if identityErr == nil && identity != c.identity {
		return nil, ErrUnavailable
	}
	if err = upgrade(ctx, tx); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if err = c.publishIdentity(); err == nil {
		err = syncDir(filepath.Dir(c.root))
	}
	if err != nil {
		return nil, err
	}
	ok = true
	return c, nil
}

// Open never initializes missing files or schema. Both identities are required.
func Open(ctx context.Context, root, identity, keyIdentity string) (*Catalog, error) {
	if !validID(identity, "restoreauth_") || !validID(keyIdentity, "keyauth_") {
		return nil, ErrInput
	}
	c, err := openDatabase(root, false)
	if err != nil {
		return nil, err
	}
	c.identity, c.keyIdentity = identity, keyIdentity
	if err = c.run(ctx, false, func(*sql.Tx) error { return nil }); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Catalog) Identity() string             { return c.identity }
func (c *Catalog) KeyAuthorityIdentity() string { return c.keyIdentity }
func (c *Catalog) Close() error                 { return c.db.Close() }

func (c *Catalog) checkFile() error {
	identity, err := readIdentity(c.root)
	if err != nil || identity != c.identity {
		return ErrUnavailable
	}
	st, err := os.Lstat(filepath.Join(c.root, "catalog.sqlite"))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return ErrUnavailable
	}
	id := st.Sys().(*syscall.Stat_t)
	if id.Uid != uint32(os.Geteuid()) || uint64(id.Dev) != c.device || id.Ino != c.inode {
		return ErrUnavailable
	}
	_, err = directory(c.root, false)
	return err
}

// Every operation obtains SQLite's cross-process write reservation. Activation
// keeps it through inspection/publication, excluding concurrent revocations and
// incarnation reservations. Callbacks must never re-enter this catalogue.
// In synchronous mode, the operation returns only once the replica holds its
// record, and it never runs on state the replica lacks (replication_linux.go).
func (c *Catalog) transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	return c.run(ctx, true, fn)
}

// run is transaction; replicated false skips the stream, for Open's check
// and for reading the stream's own state.
func (c *Catalog) run(ctx context.Context, replicated bool, fn func(*sql.Tx) error) error {
	for {
		again, err := c.attempt(ctx, replicated, fn)
		if !again || err != nil {
			return err
		}
	}
}

func (c *Catalog) attempt(ctx context.Context, replicated bool, fn func(*sql.Tx) error) (bool, error) {
	if err := c.checkFile(); err != nil {
		return false, err
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return false, errors.Join(ErrUnavailable, err)
	}
	defer tx.Rollback()
	var identity, keyIdentity string
	if err = tx.QueryRowContext(ctx, "SELECT identity,key_identity FROM authority WHERE singleton=1").Scan(&identity, &keyIdentity); err != nil {
		return false, errors.Join(ErrUnavailable, err)
	}
	if identity != c.identity || keyIdentity != c.keyIdentity {
		return false, ErrUnavailable
	}
	v, err := version(ctx, tx)
	if err != nil {
		return false, err
	}
	var state *replication
	if v >= 3 {
		if state, err = readReplication(ctx, tx); err != nil {
			return false, err
		}
	}
	if !replicated {
		state = nil
	}
	if state.armed() {
		if c.repl == nil {
			return false, errors.Join(ErrUnavailable, ErrReplicaRequired)
		}
		// The barrier: never act on a record the replica lacks.
		if state.seq > c.repl.acknowledged(state.epoch) {
			tx.Rollback()
			return true, c.repl.sync(ctx, c, state.epoch, state.seq)
		}
	}
	rec := &txRecord{state: state}
	c.recMu.Lock()
	c.recording[tx] = rec
	c.recMu.Unlock()
	defer func() {
		c.recMu.Lock()
		delete(c.recording, tx)
		c.recMu.Unlock()
	}()
	if err = fn(tx); err != nil {
		return false, err
	}
	var record authoritylog.Record
	if len(rec.ops) > 0 && state.armed() {
		if record, err = c.appendRecord(ctx, tx, state, rec.ops); err != nil {
			return false, err
		}
	}
	if err = c.checkFile(); err != nil {
		return false, err
	}
	if c.hook != nil {
		c.hook("before_commit")
	}
	if err = tx.Commit(); err != nil {
		return false, err // outcome may be unknown: callers retry the stable operation ID
	}
	if c.hook != nil {
		c.hook("after_commit")
	}
	if record.Seq == 0 {
		return false, nil
	}
	// Committed on the primary: the record is in the log with its effect.
	c.repl.metrics.Load().Committed(record.Seq)
	if err = c.repl.sync(ctx, c, state.epoch, record.Seq); err != nil {
		return false, err
	}
	if record.HasSecret() {
		c.prune(ctx, record.Seq)
	}
	return false, nil
}

// Register is trusted new-store enrollment, not recovery from missing authority
// state. Runtime integration must check existing stores before admitting work.
func (c *Catalog) Register(ctx context.Context, store, volume string) (Binding, error) {
	b := Binding{Store: store, Volume: volume, Incarnation: 1}
	if !validName(store) || !validName(volume) {
		return b, ErrInput
	}
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := c.exec(ctx, tx, stmtRegister, store, volume); err != nil {
			return err
		}
		got, sealed, err := binding(ctx, tx, store)
		if err != nil || got.Volume != volume {
			return ErrConflict
		}
		if sealed {
			return ErrSealed
		}
		b = got
		return nil
	})
	return b, err
}

func binding(ctx context.Context, tx *sql.Tx, store string) (Binding, bool, error) {
	b := Binding{Store: store}
	var sealed bool
	err := tx.QueryRowContext(ctx, "SELECT volume,incarnation,sealed FROM stores WHERE id=?", store).Scan(&b.Volume, &b.Incarnation, &sealed)
	return b, sealed, err
}

func current(ctx context.Context, tx *sql.Tx, want Binding) error {
	b, sealed, err := binding(ctx, tx, want.Store)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStale
	}
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if b != want {
		return ErrStale
	}
	if sealed {
		return ErrSealed
	}
	return nil
}

// Lookup never registers a missing store. In particular, boot/adoption cannot
// repair lost authority history by treating an existing volume as newly created.
func (c *Catalog) Lookup(ctx context.Context, store string) (Binding, error) {
	var b Binding
	if !validName(store) {
		return b, ErrInput
	}
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		var sealed bool
		var err error
		b, sealed, err = binding(ctx, tx, store)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStale
		}
		if err != nil {
			return err
		}
		if sealed {
			return ErrSealed
		}
		return nil
	})
	return b, err
}

// WithBinding serializes a trusted operation with incarnation reservation and
// permanent sealing. The callback must not re-enter this catalogue or acquire a
// host lifecycle lock: host -> catalogue -> keys/SQL is the integration order.
// This is an identity gate, not a guest fence or a restoration activation proof.
func (c *Catalog) WithBinding(ctx context.Context, b Binding, use func() error) error {
	if b.Incarnation == 0 || !validName(b.Store) || !validName(b.Volume) || use == nil {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		if err := current(ctx, tx, b); err != nil {
			return err
		}
		return use()
	})
}

// ReserveIncarnation is the root mutation of beginRestore. The coordinator must
// serialize the Ready -> Draining phase and retire the previous physical writer
// before installing an image. This reservation itself is never a retirement ACK.
func (c *Catalog) ReserveIncarnation(ctx context.Context, old Binding, operation string) (Binding, error) {
	next := old
	if !validName(operation) || old.Incarnation == 0 || old.Incarnation >= 1<<63-1 {
		return next, ErrInput
	}
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		var store string
		var previous, reserved uint64
		err := tx.QueryRowContext(ctx, "SELECT store,previous,current FROM reservations WHERE operation=?", operation).Scan(&store, &previous, &reserved)
		if err == nil {
			next.Incarnation = reserved
			if store != old.Store || previous != old.Incarnation {
				return ErrConflict
			}
			return current(ctx, tx, next)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err = current(ctx, tx, old); err != nil {
			return err
		}
		next.Incarnation++
		if _, err = c.exec(ctx, tx, stmtReserveStore, next.Incarnation, old.Store); err != nil {
			return err
		}
		_, err = c.exec(ctx, tx, stmtReserveInsert, operation, old.Store, old.Incarnation, next.Incarnation)
		return err
	})
	return next, err
}

func (c *Catalog) BeginRevocation(ctx context.Context, subject string) (uint64, error) {
	var revision uint64
	if !validName(subject) {
		return 0, ErrInput
	}
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, "SELECT revision FROM revocations WHERE subject=?", subject).Scan(&revision)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		result, err := c.exec(ctx, tx, stmtRevision)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errors.Join(ErrUnavailable, err)
		}
		if err = tx.QueryRowContext(ctx, "SELECT revision FROM authority WHERE singleton=1").Scan(&revision); err != nil {
			return err
		}
		_, err = c.exec(ctx, tx, stmtRevocation, subject, revision)
		return err
	})
	return revision, err
}

func signReceipt(r Receipt, secret []byte) []byte {
	r.MAC = nil
	b, _ := json.Marshal(r)
	m := hmac.New(sha256.New, secret)
	m.Write(b)
	return m.Sum(nil)
}

func (c *Catalog) Scan(ctx context.Context, b Binding) (Receipt, error) {
	r := Receipt{Authority: c.identity, Store: b.Store, Incarnation: b.Incarnation, Subjects: []string{}}
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if err := current(ctx, tx, b); err != nil {
			return err
		}
		var secret []byte
		if err := tx.QueryRowContext(ctx, "SELECT revision,secret FROM authority WHERE singleton=1").Scan(&r.Revision, &secret); err != nil {
			return err
		}
		defer clear(secret)
		rows, err := tx.QueryContext(ctx, "SELECT subject FROM revocations ORDER BY subject")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var subject string
			if err = rows.Scan(&subject); err != nil {
				return err
			}
			r.Subjects = append(r.Subjects, subject)
		}
		if err = rows.Err(); err != nil {
			return err
		}
		r.MAC = signReceipt(r, secret)
		return nil
	})
	return r, err
}

func (c *Catalog) validateReceipt(ctx context.Context, tx *sql.Tx, r Receipt) (uint64, error) {
	var secret []byte
	var revision uint64
	if err := tx.QueryRowContext(ctx, "SELECT revision,secret FROM authority WHERE singleton=1").Scan(&revision, &secret); err != nil {
		return 0, err
	}
	defer clear(secret)
	if r.Authority != c.identity || r.Revision > revision || !hmac.Equal(r.MAC, signReceipt(r, secret)) {
		return 0, ErrStale
	}
	b, sealed, err := binding(ctx, tx, r.Store)
	if err != nil || b.Incarnation != r.Incarnation {
		return 0, ErrStale
	}
	if sealed {
		return 0, ErrSealed
	}
	return revision, nil
}

// RecordVerifiedFence must only follow an authenticated, durable fence response
// for this exact snapshot and incarnation. The coordinator also enforces the
// Ready/Reconciling phase. Never call it merely because Scan returned a MAC.
func (c *Catalog) RecordVerifiedFence(ctx context.Context, r Receipt) error {
	return c.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := c.validateReceipt(ctx, tx, r); err != nil {
			return err
		}
		result, err := c.exec(ctx, tx, stmtFence, r.Revision, r.Store, r.Revision)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err == nil && n != 1 {
			return ErrStale
		}
		return err
	})
}

func (c *Catalog) currentFences(ctx context.Context, tx *sql.Tx, r Receipt) error {
	revision, err := c.validateReceipt(ctx, tx, r)
	if err != nil {
		return err
	}
	var ack int64
	if err = tx.QueryRowContext(ctx, "SELECT ack_revision FROM stores WHERE id=?", r.Store).Scan(&ack); err != nil {
		return err
	}
	if revision != r.Revision || ack < 0 || uint64(ack) != revision {
		return ErrStale
	}
	return nil
}

// WithCurrentFences publishes a normal boot or new enrollment after current
// guest fences. Restored activation additionally requires actual history
// inspection through Activate. Callbacks must not re-enter this catalogue.
func (c *Catalog) WithCurrentFences(ctx context.Context, r Receipt, publish func() error) error {
	if publish == nil {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		if err := c.currentFences(ctx, tx, r); err != nil {
			return err
		}
		return publish()
	})
}

func subjectBarrier(ctx context.Context, tx *sql.Tx, b Binding, subject string) (acknowledged, sealed bool, err error) {
	got, sealed, err := binding(ctx, tx, b.Store)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, ErrStale
	}
	if err != nil {
		return false, false, errors.Join(ErrUnavailable, err)
	}
	if got != b {
		return false, false, ErrStale
	}
	var revision uint64
	if err = tx.QueryRowContext(ctx, "SELECT revision FROM revocations WHERE subject=?", subject).Scan(&revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, sealed, ErrStale
		}
		return false, sealed, err
	}
	var ack int64
	if err = tx.QueryRowContext(ctx, "SELECT ack_revision FROM stores WHERE id=?", b.Store).Scan(&ack); err != nil {
		return false, sealed, err
	}
	return sealed || (ack >= 0 && uint64(ack) >= revision), sealed, nil
}

// SubjectBarrier reports independent evidence, never physical retirement by
// itself. The worker must revalidate a permanent host seal before using it.
func (c *Catalog) SubjectBarrier(ctx context.Context, b Binding, subject string) (acknowledged, sealed bool, err error) {
	err = c.transaction(ctx, func(tx *sql.Tx) error {
		var e error
		acknowledged, sealed, e = subjectBarrier(ctx, tx, b, subject)
		return e
	})
	return
}

// WithRevocation holds the independent authority stable through the SQL final
// publication. A bool restored from an old SQL backup cannot replace a current
// incarnation-bound guest ACK. New stores catch up separately before admission.
// The trusted coordinator supplies the complete immutable target manifest and
// revalidates host seals first. No host calls are allowed from publish.
func (c *Catalog) WithRevocation(ctx context.Context, subject string, targets []Binding, publish func() error) error {
	if !validName(subject) || len(targets) == 0 || publish == nil {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		for _, b := range targets {
			ack, _, err := subjectBarrier(ctx, tx, b, subject)
			if err != nil {
				return err
			}
			if !ack {
				return ErrStale
			}
		}
		return publish()
	})
}

// RecordOutcome follows a verified local commit and precedes an external success
// ACK. The coordinator checks Ready; this method rejects obsolete incarnations.
// A known ID accepts only its current result: the digest of its latest rerun,
// or else the first digest. When the outcome's loss is declared for b's
// incarnation, this delivery is its rerun and is recorded as one (RecordRerun).
// The delivery path thus needs no separate call.
func (c *Catalog) RecordOutcome(ctx context.Context, b Binding, outcome Outcome) error {
	if !validName(outcome.ID) {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		if err := current(ctx, tx, b); err != nil {
			return err
		}
		withLosses, err := lossesAvailable(ctx, tx)
		if err != nil {
			return err
		}
		if withLosses {
			lost, err := declared(ctx, tx, outcome.ID, b.Incarnation)
			if err != nil {
				return err
			}
			if lost {
				return c.recordRerun(ctx, tx, b, outcome)
			}
		}
		if _, err = c.exec(ctx, tx, stmtOutcome, outcome.ID, b.Store, outcome.Digest[:]); err != nil {
			return err
		}
		got, err := recordedOutcomes(ctx, tx, withLosses, "o.id=?", outcome.ID)
		if err != nil {
			return err
		}
		if len(got) != 1 || got[0].store != b.Store || !hmac.Equal(got[0].Digest[:], outcome.Digest[:]) {
			return ErrConflict
		}
		return nil
	})
}

// WithActivation is the model's activate: it excludes root changes while the
// trusted coordinator verifies the CURRENT restored data and publishes the
// Ready state. It refuses with ErrHistory while the image lacks a recorded
// outcome whose loss is not declared for this incarnation. It never declares
// a loss itself: the restore path is Activate. publish must still enforce
// physical/phase preconditions. No callback may re-enter this catalogue.
func (c *Catalog) WithActivation(ctx context.Context, r Receipt, inspect Inspection, publish func() error) error {
	if inspect == nil || publish == nil {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		missing, err := c.missingOutcomes(ctx, tx, r, inspect)
		if err != nil {
			return err
		}
		if err = accounted(ctx, tx, missing, r.Incarnation); err != nil {
			return err
		}
		return publish()
	})
}

// RecordRetiredSeal is trusted host input, after permanent execution retirement.
// It neither proves retirement nor deletes keys/data; the runtime must supply
// that evidence before calling it. A sealed identity can never reserve again.
func (c *Catalog) RecordRetiredSeal(ctx context.Context, b Binding) error {
	return c.transaction(ctx, func(tx *sql.Tx) error {
		got, _, err := binding(ctx, tx, b.Store)
		if err != nil || got != b {
			return ErrStale
		}
		_, err = c.exec(ctx, tx, stmtSeal, b.Store)
		return err
	})
}

// WithSubjectKey serializes a NEW subject-key grant against beginRevocation.
// Already cached keys and privileged volume-unlock/maintenance permissions are
// separate contracts. A denial here is not cryptographic destruction.
func (c *Catalog) WithSubjectKey(ctx context.Context, subject string, use func() error) error {
	if !validName(subject) || use == nil {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		var denied bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?)", subject).Scan(&denied); err != nil {
			return err
		}
		if denied {
			return ErrRevoked
		}
		return use()
	})
}

// SeparateFrom checks path separation, not independent devices or snapshot
// policy. The existing ancestor is resolved even when dataRoot is not created.
func (c *Catalog) SeparateFrom(dataRoot string) error {
	return CheckSeparation(c.root, dataRoot)
}

// CheckSeparation is also available before administrative initialization, so an
// invalid restore-domain configuration need not create authority files.
func CheckSeparation(authorityRoot, dataRoot string) error {
	authority, err := candidatePath(authorityRoot)
	if err != nil {
		return err
	}
	data, err := candidatePath(dataRoot)
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{authority, data}, {data, authority}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return ErrInput
		}
	}
	return nil
}

func candidatePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil || path == "" {
		return "", ErrInput
	}
	ancestor := abs
	for {
		if _, err = os.Lstat(ancestor); err == nil {
			real, err := filepath.EvalSymlinks(ancestor)
			if err != nil {
				return "", err
			}
			suffix, err := filepath.Rel(ancestor, abs)
			if err != nil {
				return "", err
			}
			abs = filepath.Join(real, suffix)
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		ancestor = filepath.Dir(ancestor)
	}
	return abs, nil
}
