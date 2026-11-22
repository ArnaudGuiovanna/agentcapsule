//go:build linux && cgo

package restoreauthority

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
)

// The scope of a revocation subject (docs/adr/006-authority-service.md,
// "Changes after the v0.1.0 audit"). Until then a store was fenced with
// every subject the authority ever recorded, at every boot: the cost of a
// boot grew with the platform's whole revocation history, and every guest
// received other organizations' subject IDs.
//
// A store can act only on the subjects of the events it receives: its own
// agent's, those of the requests it is a party to and of the agents it shares
// them with, and those of the events addressed to it. The worker names these
// stores when it begins a revocation (Scope), from PostgreSQL, after the
// subject's commit there: no new request can then join a deleted agent, and a
// request's parties and an event's destination never change. The catalogue
// records one row per store of the scope, with the revision that added it.
// A subject begun without a scope is in every store's (the wildcard row), and
// so is each subject begun before schema version 5, which has no row at all.
//
// A store's acknowledged revision then means: the store holds a durable fence
// of every subject in its scope added at or below it. A scan returns only the
// subjects of the store's scope above that revision, in pages: a boot costs
// what was revoked for this store since its last boot, nothing for another
// organization's revocations.

// Scope is a revocation subject and the stores that can act on it. No store
// means every store: the scope is unknown.
type Scope struct {
	Subject string   `json:"subject"`
	Stores  []string `json:"stores,omitempty"`
}

// scopeVersion is the schema version of the scope rows.
const scopeVersion = 5

// scopeSchema is version 5: the scope of each revocation subject. A
// subject's rows never change; a later begin may only add stores, under a new
// revision.
const scopeSchema = `
CREATE TABLE revocation_scopes (
 subject TEXT NOT NULL REFERENCES revocations(subject),
 store TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 PRIMARY KEY(subject,store)
);
CREATE INDEX revocation_scopes_by_store ON revocation_scopes(store,revision);
PRAGMA user_version=5;
`

// Bounds of the scope operations.
const (
	// MaxScopes bounds the subjects of one BeginRevocations.
	MaxScopes = 1000
	// MaxScopeStores bounds the stores of one subject's scope in one call.
	MaxScopeStores = 10000
	// ScanPage bounds the subjects of one receipt, and ScanBytes their
	// encoded size: a receipt goes back in a request frame.
	ScanPage  = 4096
	ScanBytes = 2 << 20
)

func scoped(ctx context.Context, tx *sql.Tx) (bool, error) {
	v, err := version(ctx, tx)
	return v >= scopeVersion, err
}

// normalScopes validates scopes, and sorts and deduplicates each one's stores.
func normalScopes(scopes []Scope) ([]Scope, error) {
	if len(scopes) == 0 || len(scopes) > MaxScopes {
		return nil, ErrInput
	}
	out := make([]Scope, len(scopes))
	for i, s := range scopes {
		if !validName(s.Subject) || len(s.Stores) > MaxScopeStores {
			return nil, ErrInput
		}
		stores := slices.Clone(s.Stores)
		slices.Sort(stores)
		stores = slices.Compact(stores)
		for _, store := range stores {
			if !validName(store) {
				return nil, ErrInput
			}
		}
		if len(stores) == 0 {
			stores = []string{wildcard}
		}
		out[i] = Scope{Subject: s.Subject, Stores: stores}
	}
	return out, nil
}

// missingScope returns, for each scope, the stores its subject's rows lack;
// every store of a subject not yet begun. A subject in every store's scope
// already lacks none, and so does any subject on a catalogue older than
// version 5, where every subject is.
func missingScope(ctx context.Context, tx *sql.Tx, scopes []Scope) ([]Scope, error) {
	withScopes, err := scoped(ctx, tx)
	if err != nil {
		return nil, err
	}
	var missing []Scope
	for _, s := range scopes {
		var known bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?)", s.Subject).Scan(&known); err != nil {
			return nil, err
		}
		if !known {
			missing = append(missing, s)
			continue
		}
		if !withScopes {
			continue
		}
		rows, err := tx.QueryContext(ctx, "SELECT store FROM revocation_scopes WHERE subject=?", s.Subject)
		if err != nil {
			return nil, err
		}
		have := map[string]bool{}
		for rows.Next() {
			var store string
			if err = rows.Scan(&store); err != nil {
				rows.Close()
				return nil, err
			}
			have[store] = true
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return nil, err
		}
		if len(have) == 0 || have[wildcard] {
			continue // before version 5, or already in every store's scope
		}
		var add []string
		for _, store := range s.Stores {
			if !have[store] {
				add = append(add, store)
			}
		}
		if len(add) > 0 {
			missing = append(missing, Scope{Subject: s.Subject, Stores: add})
		}
	}
	return missing, nil
}

// KnownScopes reports whether every subject of scopes is begun with every
// store of its scope: then BeginRevocations writes nothing.
func (c *Catalog) KnownScopes(ctx context.Context, scopes []Scope) (bool, error) {
	scopes, err := normalScopes(scopes)
	if err != nil {
		return false, err
	}
	var missing []Scope
	err = c.transaction(ctx, func(tx *sql.Tx) error {
		missing, err = missingScope(ctx, tx, scopes)
		return err
	})
	return len(missing) == 0, err
}

// BeginRevocations begins each subject of scopes, or adds the stores its
// scope lacks, in one transaction: one write and one record of the stream.
// Each subject begun, and each addition, takes the next revision. A subject
// already in every store's scope stays there. It waits for the fences holds
// and activations of the stores it adds.
func (c *Catalog) BeginRevocations(ctx context.Context, scopes []Scope) error {
	scopes, err := normalScopes(scopes)
	if err != nil {
		return err
	}
	var missing []Scope
	if err = c.transaction(ctx, func(tx *sql.Tx) error {
		missing, err = missingScope(ctx, tx, scopes)
		return err
	}); err != nil || len(missing) == 0 {
		return err
	}
	var locks []lockRequest
	for _, s := range missing {
		for _, store := range s.Stores {
			locks = append(locks, widensScope(store))
		}
	}
	return c.holding(ctx, locks, func() error {
		return c.operate(ctx, authoritylog.WriteRevocationStart, func(tx *sql.Tx) error {
			missing, err := missingScope(ctx, tx, missing)
			if err != nil {
				return err
			}
			withScopes, err := scoped(ctx, tx)
			if err != nil {
				return err
			}
			for _, s := range missing {
				var known bool
				if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM revocations WHERE subject=?)", s.Subject).Scan(&known); err != nil {
					return err
				}
				revision, err := c.nextRevision(ctx, tx)
				if err != nil {
					return err
				}
				if !known {
					if _, err = c.exec(ctx, tx, stmtRevocation, s.Subject, revision); err != nil {
						return err
					}
				}
				if !withScopes {
					continue
				}
				for _, store := range s.Stores {
					if _, err = c.exec(ctx, tx, stmtScope, s.Subject, store, revision); err != nil {
						return err
					}
				}
			}
			return nil
		})
	})
}

func (c *Catalog) nextRevision(ctx context.Context, tx *sql.Tx) (uint64, error) {
	result, err := c.exec(ctx, tx, stmtRevision)
	if err != nil {
		return 0, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return 0, errors.Join(ErrUnavailable, err)
	}
	var revision uint64
	err = tx.QueryRowContext(ctx, "SELECT revision FROM authority WHERE singleton=1").Scan(&revision)
	return revision, err
}

// legacyRevision is the highest revision of a subject without any scope row:
// one begun before version 5, in every store's scope. It is computed once per
// handle: nothing this binary writes adds such a subject.
func (c *Catalog) legacyRevision(ctx context.Context, tx *sql.Tx) (uint64, error) {
	c.legacyOnce.Lock()
	defer c.legacyOnce.Unlock()
	if c.legacyKnown {
		return c.legacy, nil
	}
	withScopes, err := scoped(ctx, tx)
	if err != nil || !withScopes {
		return 0, err
	}
	var legacy sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT max(revision) FROM revocations r
        WHERE NOT EXISTS(SELECT 1 FROM revocation_scopes s WHERE s.subject=r.subject)`).Scan(&legacy); err != nil {
		return 0, err
	}
	c.legacy, c.legacyKnown = uint64(legacy.Int64), true
	return c.legacy, nil
}

type scopeRow struct {
	subject  string
	revision uint64
}

// scopeRows returns the subjects of store's scope added above after, up to
// upTo, in revision order, at most limit of them (none when limit is 0).
func (c *Catalog) scopeRows(ctx context.Context, tx *sql.Tx, store string, after int64, upTo uint64, limit int) ([]scopeRow, error) {
	withScopes, err := scoped(ctx, tx)
	if err != nil {
		return nil, err
	}
	var queries []struct {
		sql  string
		args []any
	}
	add := func(q string, args ...any) {
		queries = append(queries, struct {
			sql  string
			args []any
		}{q, args})
	}
	if !withScopes {
		add("SELECT subject,revision FROM revocations WHERE revision>? AND revision<=? ORDER BY revision LIMIT ?", after, upTo, limit)
	} else {
		for _, s := range []string{store, wildcard} {
			add("SELECT subject,revision FROM revocation_scopes WHERE store=? AND revision>? AND revision<=? ORDER BY revision LIMIT ?", s, after, upTo, limit)
		}
		legacy, err := c.legacyRevision(ctx, tx)
		if err != nil {
			return nil, err
		}
		if after < int64(legacy) {
			add(`SELECT subject,revision FROM revocations r WHERE revision>? AND revision<=? AND NOT EXISTS
                (SELECT 1 FROM revocation_scopes s WHERE s.subject=r.subject) ORDER BY revision LIMIT ?`, after, min(upTo, legacy), limit)
		}
	}
	var out []scopeRow
	for _, q := range queries {
		rows, err := tx.QueryContext(ctx, q.sql, q.args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r scopeRow
			if err = rows.Scan(&r.subject, &r.revision); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, r)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b scopeRow) int { return cmp.Compare(a.revision, b.revision) })
	if limit >= 0 {
		out = out[:min(len(out), limit)]
	}
	return out, nil
}

// scopeMax is the highest revision that added a subject to store's scope: a
// fences hold or an activation is current only if the store acknowledged it.
// Before version 5 it is the catalogue's revision, as every subject is in
// every scope.
func (c *Catalog) scopeMax(ctx context.Context, tx *sql.Tx, store string, revision uint64) (uint64, error) {
	withScopes, err := scoped(ctx, tx)
	if err != nil || !withScopes {
		return revision, err
	}
	highest, err := c.legacyRevision(ctx, tx)
	if err != nil {
		return 0, err
	}
	for _, s := range []string{store, wildcard} {
		var r sql.NullInt64
		if err = tx.QueryRowContext(ctx, "SELECT max(revision) FROM revocation_scopes WHERE store=?", s).Scan(&r); err != nil {
			return 0, err
		}
		highest = max(highest, uint64(r.Int64))
	}
	return highest, nil
}

// subjectInScope returns the lowest revision at which subject entered
// store's scope; in is false when it is outside it: no event of store can
// name it. A subject not begun is stale.
func subjectInScope(ctx context.Context, tx *sql.Tx, store, subject string) (revision uint64, in bool, err error) {
	if err = tx.QueryRowContext(ctx, "SELECT revision FROM revocations WHERE subject=?", subject).Scan(&revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, ErrStale
		}
		return 0, false, err
	}
	withScopes, err := scoped(ctx, tx)
	if err != nil || !withScopes {
		return revision, true, err
	}
	var lowest sql.NullInt64
	var rows int
	if err = tx.QueryRowContext(ctx, "SELECT min(CASE WHEN store IN (?,?) THEN revision END),count(*) FROM revocation_scopes WHERE subject=?",
		store, wildcard, subject).Scan(&lowest, &rows); err != nil {
		return 0, false, err
	}
	switch {
	case lowest.Valid:
		return uint64(lowest.Int64), true, nil
	case rows == 0:
		return revision, true, nil // begun before version 5: every store's
	}
	return 0, false, nil
}

// pageOf cuts rows to one receipt: at most ScanPage subjects and ScanBytes
// of their encoding. more reports that rows went on past the cut.
func pageOf(rows []scopeRow) (page []scopeRow, more bool) {
	size := 0
	for i, r := range rows {
		b, _ := json.Marshal(r.subject)
		if i == ScanPage || size+len(b)+1 > ScanBytes {
			return rows[:i], true
		}
		size += len(b) + 1
	}
	return rows, false
}
