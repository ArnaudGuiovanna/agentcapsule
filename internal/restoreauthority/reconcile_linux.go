//go:build linux && cgo

package restoreauthority

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// What the reconciliation reads from the authority after a failover
// (docs/adr/005-keys-outside-restored-domain.md, "What the code must do",
// item 15; docs/adr/006-authority-service.md §7, wave 7). PostgreSQL may be
// older than the authority by the database's window: agentcapsule-admin
// reconcile reads the access revocation records, the revocation subjects and
// the stores here, page by page, and brings PostgreSQL up to them before the
// API opens. Each read runs in one catalogue transaction; a page names the
// cursor of the next one (the table's rowid: rows are never deleted, and a
// catalogue keeps their order).

// MaxExportPage bounds the rows of one page.
const MaxExportPage = 500

// maxExportBytes bounds a page of access records, well within a frame of
// the authority service's socket.
const maxExportBytes = 2 << 20

// ExportedAccess is an access revocation record as the reconciliation reads
// it: the record, and how far it has gone (AccessStatus).
type ExportedAccess struct {
	AccessRecord
	OnReplica bool `json:"on_replica"`
	Degraded  bool `json:"degraded"`
}

// Subject is a revocation subject and its revision.
type Subject struct {
	Subject  string `json:"subject"`
	Revision uint64 `json:"revision"`
}

// Store is a store as the authority knows it: its volume, its incarnation,
// and whether it is sealed for good.
type Store struct {
	ID          string `json:"id"`
	Volume      string `json:"volume"`
	Incarnation uint64 `json:"incarnation"`
	Sealed      bool   `json:"sealed"`
}

func pageLimit(limit int) int {
	if limit <= 0 || limit > MaxExportPage {
		return MaxExportPage
	}
	return limit
}

// ExportAccess returns the access revocation records after the cursor
// after, at most limit, and the cursor of the next page: 0 when this one is
// the last.
func (c *Catalog) ExportAccess(ctx context.Context, after int64, limit int) ([]ExportedAccess, int64, error) {
	if after < 0 {
		return nil, 0, ErrInput
	}
	limit = pageLimit(limit)
	out := []ExportedAccess{}
	var next int64
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		out, next = out[:0], 0
		cursor := after
		if v, err := version(ctx, tx); err != nil || v < schemaVersion {
			return errors.Join(ErrUpgradeRequired, err)
		}
		rows, err := tx.QueryContext(ctx, "SELECT rowid,id,kind,organization,objects,recorded_at,epoch,seq FROM access_revocations WHERE rowid>? ORDER BY rowid LIMIT ?", cursor, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		size := 0
		for rows.Next() {
			var rowid int64
			var r ExportedAccess
			var objects string
			if err = rows.Scan(&rowid, &r.ID, &r.Kind, &r.Organization, &objects, &r.RecordedAt, &r.Epoch, &r.Seq); err != nil {
				return err
			}
			if len(out) == limit || (len(out) > 0 && size+len(objects) > maxExportBytes) {
				next = cursor
				break
			}
			if err = json.Unmarshal([]byte(objects), &r.Objects); err != nil {
				return errors.Join(ErrUnavailable, err)
			}
			size += len(objects) + 256
			out = append(out, r)
			cursor = rowid
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].OnReplica, out[i].Degraded = c.accessProgress(out[i].AccessRecord)
	}
	return out, next, nil
}

// ExportSubjects returns the revocation subjects after the cursor after.
func (c *Catalog) ExportSubjects(ctx context.Context, after int64, limit int) ([]Subject, int64, error) {
	if after < 0 {
		return nil, 0, ErrInput
	}
	limit = pageLimit(limit)
	out := []Subject{}
	var next int64
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		out, next = out[:0], 0
		cursor := after
		rows, err := tx.QueryContext(ctx, "SELECT rowid,subject,revision FROM revocations WHERE rowid>? ORDER BY rowid LIMIT ?", cursor, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rowid int64
			var s Subject
			if err = rows.Scan(&rowid, &s.Subject, &s.Revision); err != nil {
				return err
			}
			if len(out) == limit {
				next = cursor
				break
			}
			out = append(out, s)
			cursor = rowid
		}
		return rows.Err()
	})
	return out, next, err
}

// ExportStores returns the stores after the cursor after.
func (c *Catalog) ExportStores(ctx context.Context, after int64, limit int) ([]Store, int64, error) {
	if after < 0 {
		return nil, 0, ErrInput
	}
	limit = pageLimit(limit)
	out := []Store{}
	var next int64
	err := c.transaction(ctx, func(tx *sql.Tx) error {
		out, next = out[:0], 0
		cursor := after
		rows, err := tx.QueryContext(ctx, "SELECT rowid,id,volume,incarnation,sealed FROM stores WHERE rowid>? ORDER BY rowid LIMIT ?", cursor, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rowid int64
			var s Store
			if err = rows.Scan(&rowid, &s.ID, &s.Volume, &s.Incarnation, &s.Sealed); err != nil {
				return err
			}
			if len(out) == limit {
				next = cursor
				break
			}
			out = append(out, s)
			cursor = rowid
		}
		return rows.Err()
	})
	return out, next, err
}
