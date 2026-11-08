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
	"syscall"

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
)

type Catalog struct {
	db             *sql.DB
	root, identity string
	keyIdentity    string
	device, inode  uint64
	hook           func(string) // tests interrupt the actual transaction boundary
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
	for k, v := range map[string]string{"mode": "rw", "_journal_mode": "DELETE", "_synchronous": "FULL", "_foreign_keys": "on", "_busy_timeout": "5000", "_txlock": "immediate"} {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	id := st.Sys().(*syscall.Stat_t)
	return &Catalog{db: db, root: abs, device: uint64(id.Dev), inode: id.Ino}, nil
}

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
		if _, err = tx.ExecContext(ctx, schema); err != nil {
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
	if err = c.transaction(ctx, func(*sql.Tx) error { return nil }); err != nil {
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
func (c *Catalog) transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	if err := c.checkFile(); err != nil {
		return err
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	defer tx.Rollback()
	var identity, keyIdentity string
	if err = tx.QueryRowContext(ctx, "SELECT identity,key_identity FROM authority WHERE singleton=1").Scan(&identity, &keyIdentity); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if identity != c.identity || keyIdentity != c.keyIdentity {
		return ErrUnavailable
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = c.checkFile(); err != nil {
		return err
	}
	if c.hook != nil {
		c.hook("before_commit")
	}
	if err = tx.Commit(); err != nil {
		return err // outcome may be unknown: callers retry the stable operation ID
	}
	if c.hook != nil {
		c.hook("after_commit")
	}
	return nil
}

// Register is trusted new-store enrollment, not recovery from missing authority
// state. Runtime integration must check existing stores before admitting work.
func (c *Catalog) Register(ctx context.Context, store, volume string) (Binding, error) {
	b := Binding{Store: store, Volume: volume, Incarnation: 1}
	if !validName(store) || !validName(volume) {
		return b, ErrInput
	}
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO stores(id,volume,incarnation) VALUES(?,?,1) ON CONFLICT DO NOTHING", store, volume); err != nil {
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
		if _, err = tx.ExecContext(ctx, "UPDATE stores SET incarnation=?,ack_revision=-1 WHERE id=?", next.Incarnation, old.Store); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO reservations VALUES(?,?,?,?)", operation, old.Store, old.Incarnation, next.Incarnation)
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
		if err = tx.QueryRowContext(ctx, "UPDATE authority SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision").Scan(&revision); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO revocations VALUES(?,?)", subject, revision)
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
		result, err := tx.ExecContext(ctx, "UPDATE stores SET ack_revision=? WHERE id=? AND ack_revision<=?", r.Revision, r.Store, r.Revision)
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
// inspection through WithActivation. Callbacks must not re-enter this catalogue.
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
func (c *Catalog) RecordOutcome(ctx context.Context, b Binding, outcome Outcome) error {
	if !validName(outcome.ID) {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		if err := current(ctx, tx, b); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO outcomes VALUES(?,?,?) ON CONFLICT(id) DO NOTHING", outcome.ID, b.Store, outcome.Digest[:]); err != nil {
			return err
		}
		var store string
		var digest []byte
		if err := tx.QueryRowContext(ctx, "SELECT store,digest FROM outcomes WHERE id=?", outcome.ID).Scan(&store, &digest); err != nil {
			return err
		}
		if store != b.Store || !hmac.Equal(digest, outcome.Digest[:]) {
			return ErrConflict
		}
		return nil
	})
}

// WithActivation excludes root changes while the trusted coordinator verifies
// the CURRENT restored data and publishes the Ready state. inspect must check
// real effects AND deduplication/results, not just IDs. publish must still enforce
// physical/phase preconditions. No callback may re-enter this catalogue.
func (c *Catalog) WithActivation(ctx context.Context, r Receipt, inspect func([]Outcome) error, publish func() error) error {
	if inspect == nil || publish == nil {
		return ErrInput
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
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
		rows, err := tx.QueryContext(ctx, "SELECT id,digest FROM outcomes WHERE store=? ORDER BY id", r.Store)
		if err != nil {
			return err
		}
		required := []Outcome{}
		for rows.Next() {
			var o Outcome
			var digest []byte
			if err = rows.Scan(&o.ID, &digest); err != nil || len(digest) != 32 {
				rows.Close()
				return ErrUnavailable
			}
			copy(o.Digest[:], digest)
			required = append(required, o)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if err = inspect(required); err != nil {
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
		_, err = tx.ExecContext(ctx, "UPDATE stores SET sealed=1 WHERE id=?", b.Store)
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
