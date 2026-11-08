// Package harnessstore atomically commits local SQL mutations, deduplication,
// and replayable results in a harness's own SQLite database.
//
// This is not a transaction coordinator for PostgreSQL or external services.
// Callers must authenticate envelopes and derive all fence subjects themselves.
// Mutation callbacks may only modify this database through the provided SQL
// interface; HTTP calls, other files, explicit transaction control, and writes
// to capsule_* tables violate the contract.
package harnessstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrConflict      = errors.New("event ID reused with a different envelope")
	ErrFenced        = errors.New("event participant has been revoked")
	ErrCommitUnknown = errors.New("commit outcome unknown; retry the same event ID and envelope")
)

// SQL deliberately omits Commit and Rollback. The store owns the transaction.
type SQL interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type transactionView struct{ tx *sql.Tx }

func (v transactionView) ExecContext(c context.Context, q string, a ...any) (sql.Result, error) {
	return v.tx.ExecContext(c, q, a...)
}
func (v transactionView) QueryContext(c context.Context, q string, a ...any) (*sql.Rows, error) {
	return v.tx.QueryContext(c, q, a...)
}
func (v transactionView) QueryRowContext(c context.Context, q string, a ...any) *sql.Row {
	return v.tx.QueryRowContext(c, q, a...)
}

// Subjects must include every participant whose revocation invalidates the work,
// e.g. agent/sender, agent/recipient, request/ID. They are part of the stored hash.
type Event struct {
	ID       string
	Subjects []string
	Body     []byte
}

type Receipt struct {
	Result   []byte
	Replayed bool
}

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS capsule_inbox (
  event_id TEXT PRIMARY KEY NOT NULL,
  envelope_hash BLOB NOT NULL CHECK(length(envelope_hash) = 32),
  result BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS capsule_fences (
  subject TEXT PRIMARY KEY NOT NULL
);`

// Open requires an existing private harness directory on storage honoring locks
// and flushes. Provisioning/mounting that directory is the runtime's responsibility.
// WAL + FULL are configured on EVERY connection, including future pool entries.
// An ACK must never be emitted until Apply or Fence returns without error.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" || path == ":memory:" {
		return nil, errors.New("a durable database file path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parent, err := os.Stat(filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("existing harness directory required: %w", err)
	}
	if !parent.IsDir() {
		return nil, fmt.Errorf("harness parent is not a directory: %s", filepath.Dir(abs))
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: abs}
	q := u.Query()
	q.Set("_journal_mode", "WAL")
	q.Set("_synchronous", "FULL")
	q.Set("_txlock", "immediate")
	q.Set("_busy_timeout", "5000")
	q.Set("_foreign_keys", "on")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	s := &Store{db: db}
	tx, err := s.begin(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, schema); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	// Persist the newly created database/WAL directory entries before any ACK.
	// This does not prove the VM disk/host/device honors flushes; integration
	// tests on the actual storage path remain necessary.
	directory, err := os.Open(filepath.Dir(abs))
	if err == nil {
		err = directory.Sync()
		closeErr := directory.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("persist database directory: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Local serializes application bookkeeping with durable revocation. It is for
// resumable background work between deliveries; incoming effects must use Apply
// to retain event deduplication. Like Apply, callbacks may only access this SQL
// transaction, never the network. A later outbound RPC must independently be
// authorized by the control plane: this transaction is not a remote lease.
func (s *Store) Local(ctx context.Context, subjects []string, mutate func(SQL) error) error {
	if len(subjects) == 0 || mutate == nil {
		return errors.New("fence subjects and SQL mutation are required")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, subject := range subjects {
		if subject == "" {
			return errors.New("empty fence subject")
		}
		var fenced bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM capsule_fences WHERE subject=?)", subject).Scan(&fenced); err != nil {
			return err
		}
		if fenced {
			return ErrFenced
		}
	}
	if err = mutate(transactionView{tx}); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return errors.Join(ErrCommitUnknown, err)
	}
	return nil
}

func (s *Store) begin(ctx context.Context) (*sql.Tx, error) {
	// Driver DSN maps this to BEGIN IMMEDIATE: take the writer lock before reads.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var journal string
	var synchronous int
	if err = tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err == nil {
		err = tx.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous)
	}
	if err == nil && (strings.ToLower(journal) != "wal" || synchronous != 2) {
		err = fmt.Errorf("unsafe SQLite settings: journal=%s synchronous=%d", journal, synchronous)
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func canonical(e Event) ([]string, [32]byte, error) {
	if e.ID == "" || len(e.Subjects) == 0 {
		return nil, [32]byte{}, errors.New("event ID and fence subjects are required")
	}
	subjects := slices.Clone(e.Subjects)
	slices.Sort(subjects)
	subjects = slices.Compact(subjects)
	if subjects[0] == "" {
		return nil, [32]byte{}, errors.New("empty fence subject")
	}
	body := e.Body
	if body == nil {
		body = []byte{}
	}
	b, err := json.Marshal(struct {
		Version  int
		Subjects []string
		Body     []byte
	}{1, subjects, body})
	return subjects, sha256.Sum256(b), err
}

// Apply returns only after the effect, inbox marker and result have committed.
// An error is never an ACK. After an ambiguous commit, retry the identical event.
func (s *Store) Apply(ctx context.Context, event Event, mutate func(context.Context, SQL) ([]byte, error)) (Receipt, error) {
	if mutate == nil {
		return Receipt{}, errors.New("SQL mutation is required")
	}
	subjects, digest, err := canonical(event)
	if err != nil {
		return Receipt{}, err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	// Fence check and effect share the same writer transaction. A later Fence
	// must wait for this commit; an earlier Fence prevents this effect entirely.
	for _, subject := range subjects {
		var fenced int
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM capsule_fences WHERE subject = ?)", subject).Scan(&fenced); err != nil {
			return Receipt{}, err
		}
		if fenced != 0 {
			return Receipt{}, ErrFenced
		}
	}
	var oldDigest, result []byte
	err = tx.QueryRowContext(ctx, "SELECT envelope_hash, result FROM capsule_inbox WHERE event_id = ?", event.ID).Scan(&oldDigest, &result)
	if err == nil {
		if !bytes.Equal(oldDigest, digest[:]) {
			return Receipt{}, ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return Receipt{}, errors.Join(ErrCommitUnknown, err)
		}
		return Receipt{Result: result, Replayed: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, err
	}
	result, err = mutate(ctx, transactionView{tx})
	if err != nil {
		return Receipt{}, err
	}
	if result == nil {
		result = []byte{}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO capsule_inbox(event_id, envelope_hash, result) VALUES (?, ?, ?)", event.ID, digest[:], result); err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, errors.Join(ErrCommitUnknown, err)
	}
	return Receipt{Result: result}, nil
}

// Fence durably revokes a subject in THIS store. It is idempotent and irreversible.
// Its success is not evidence that any other store has received the revocation.
func (s *Store) Fence(ctx context.Context, subject string) error {
	if subject == "" {
		return errors.New("fence subject is required")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO capsule_fences(subject) VALUES (?) ON CONFLICT(subject) DO NOTHING", subject); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return errors.Join(ErrCommitUnknown, err)
	}
	return nil
}
