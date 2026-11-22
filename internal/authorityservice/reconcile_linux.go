//go:build linux && cgo

package authorityservice

import (
	"context"
	"encoding/json"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// The reconciliation and the announcement (docs/adr/006-authority-service.md
// §7, wave 7; ADR 005, "What the code must do", items 14 and 15), on both
// sockets: agentcapsule-admin reconcile runs as the API's account. It reads
// the access revocation records, the revocation subjects and the stores page
// by page, and the announcement of the current epoch; it writes back the
// revocation subjects that PostgreSQL holds and the authority lacks
// (import_subjects), and the access revocation records the same way
// (append_access). None needs a hold.

// The operations of wave 7.
const (
	OpExportAccess   = "export_access"
	OpExportSubjects = "export_subjects"
	OpExportStores   = "export_stores"
	OpAnnouncement   = "announcement"
	OpImportSubjects = "import_subjects"
)

// MaxImportSubjects bounds the subjects of one import_subjects request.
const MaxImportSubjects = 1000

// The arguments and results of wave 7.
type (
	// PageArgs asks for the page after the cursor After (0 for the first),
	// at most Limit rows (restoreauthority.MaxExportPage when 0).
	PageArgs struct {
		After int64 `json:"after"`
		Limit int   `json:"limit,omitempty"`
	}
	// SubjectsArgs are revocation subjects to begin in the authority.
	// Scopes names the stores of some of them (restoreauthority.Scope); a
	// subject without one is begun in every store's scope.
	SubjectsArgs struct {
		Subjects []string                 `json:"subjects"`
		Scopes   []restoreauthority.Scope `json:"scopes,omitempty"`
	}

	// Each page names the cursor of the next one; 0 after the last.
	AccessPage struct {
		Records []restoreauthority.ExportedAccess `json:"records"`
		Next    int64                             `json:"next"`
	}
	SubjectsPage struct {
		Subjects []restoreauthority.Subject `json:"subjects"`
		Next     int64                      `json:"next"`
	}
	StoresPage struct {
		Stores []restoreauthority.Store `json:"stores"`
		Next   int64                    `json:"next"`
	}
	AnnouncementResult struct {
		Announcement restoreauthority.Announcement `json:"announcement"`
	}
	// ImportResult counts the subjects the authority did not hold.
	ImportResult struct {
		Begun int `json:"begun"`
	}
)

func init() {
	operations[OpExportAccess] = operation{api: true, run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[PageArgs](raw)
		if err != nil {
			return nil, err
		}
		records, next, err := s.c.Catalog.ExportAccess(ctx, a.After, a.Limit)
		return AccessPage{records, next}, err
	}}
	operations[OpExportSubjects] = operation{api: true, run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[PageArgs](raw)
		if err != nil {
			return nil, err
		}
		subjects, next, err := s.c.Catalog.ExportSubjects(ctx, a.After, a.Limit)
		return SubjectsPage{subjects, next}, err
	}}
	operations[OpExportStores] = operation{api: true, run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[PageArgs](raw)
		if err != nil {
			return nil, err
		}
		stores, next, err := s.c.Catalog.ExportStores(ctx, a.After, a.Limit)
		return StoresPage{stores, next}, err
	}}
	operations[OpAnnouncement] = operation{api: true, run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		if _, err := decode[struct{}](raw); err != nil {
			return nil, err
		}
		a, err := s.c.Catalog.Announcement(ctx)
		return AnnouncementResult{a}, err
	}}
	// import_subjects begins, in the authority, each subject it does not
	// hold: a revocation subject PostgreSQL's WAL shipped and the old
	// primary's authority lost. A new subject waits the quiet period, as
	// begin_revocation does. The new subjects are begun in one transaction.
	operations[OpImportSubjects] = operation{api: true, run: func(ctx context.Context, s *Server, raw json.RawMessage, _ *hold) (any, error) {
		a, err := decode[SubjectsArgs](raw)
		if err != nil {
			return nil, err
		}
		if len(a.Subjects) == 0 || len(a.Subjects) > MaxImportSubjects || len(a.Scopes) > MaxImportSubjects {
			return nil, restoreauthority.ErrInput
		}
		stores := map[string][]string{}
		for _, scope := range a.Scopes {
			stores[scope.Subject] = scope.Stores
		}
		var begin []restoreauthority.Scope
		seen := map[string]bool{}
		for _, subject := range a.Subjects {
			known, err := s.local.KnownSubject(ctx, subject)
			if err != nil {
				return nil, err
			}
			if known || seen[subject] {
				continue
			}
			seen[subject] = true
			begin = append(begin, restoreauthority.Scope{Subject: subject, Stores: stores[subject]})
		}
		if len(begin) == 0 {
			return ImportResult{0}, nil
		}
		if err = s.quiet(ctx, s.subjectsAfter); err != nil {
			return nil, err
		}
		if err = s.local.BeginRevocations(ctx, begin); err != nil {
			return nil, err
		}
		return ImportResult{len(begin)}, nil
	}}
}
