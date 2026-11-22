//go:build linux && cgo

package authorityclient

import (
	"context"
	"time"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// The reconciliation and the announcement (docs/adr/006-authority-service.md
// §7, wave 7), on either socket.

// ExportAccess is one page of export_access.
func (c *Client) ExportAccess(ctx context.Context, after int64) ([]restoreauthority.ExportedAccess, int64, error) {
	var res svc.AccessPage
	err := c.call(ctx, svc.OpExportAccess, svc.PageArgs{After: after}, &res)
	return res.Records, res.Next, err
}

// ExportSubjects is one page of export_subjects.
func (c *Client) ExportSubjects(ctx context.Context, after int64) ([]restoreauthority.Subject, int64, error) {
	var res svc.SubjectsPage
	err := c.call(ctx, svc.OpExportSubjects, svc.PageArgs{After: after}, &res)
	return res.Subjects, res.Next, err
}

// ExportStores is one page of export_stores.
func (c *Client) ExportStores(ctx context.Context, after int64) ([]restoreauthority.Store, int64, error) {
	var res svc.StoresPage
	err := c.call(ctx, svc.OpExportStores, svc.PageArgs{After: after}, &res)
	return res.Stores, res.Next, err
}

// Announcement is what the promotion to the service's epoch announced.
func (c *Client) Announcement(ctx context.Context) (restoreauthority.Announcement, error) {
	var res svc.AnnouncementResult
	err := c.call(ctx, svc.OpAnnouncement, struct{}{}, &res)
	return res.Announcement, err
}

// ImportSubjects begins, in the authority, each subject it does not hold.
// It returns how many were new.
func (c *Client) ImportSubjects(ctx context.Context, subjects []string) (int, error) {
	return c.importSubjects(ctx, subjects, nil)
}

// importSubjects is ImportSubjects with the scopes of the subjects, in the
// order of subjects; nil when none is known.
func (c *Client) importSubjects(ctx context.Context, subjects []string, scopes []restoreauthority.Scope) (int, error) {
	begun := 0
	for i := 0; i < len(subjects); i += svc.MaxImportSubjects {
		end := min(i+svc.MaxImportSubjects, len(subjects))
		args := svc.SubjectsArgs{Subjects: subjects[i:end]}
		if scopes != nil {
			args.Scopes = scopes[i:end]
		}
		var res svc.ImportResult
		if err := c.call(ctx, svc.OpImportSubjects, args, &res); err != nil {
			return begun, err
		}
		begun += res.Begun
	}
	return begun, nil
}

// pages reads every page of an export, from the first.
func pages[T any](ctx context.Context, page func(context.Context, int64) ([]T, int64, error)) ([]T, error) {
	var out []T
	for after := int64(0); ; {
		items, next, err := page(ctx, after)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if next == 0 {
			return out, nil
		}
		if next <= after {
			return nil, svc.ErrorOf(svc.CodeProtocol)
		}
		after = next
	}
}

// The API's client is the reconciliation's authority: agentcapsule-admin
// reconcile runs as the API's account, on the API socket.
var _ controlplane.ReconciliationAuthority = (*API)(nil)

// AuthorityEpoch gives the restore authority's identity and epoch.
func (a *API) AuthorityEpoch(ctx context.Context) (string, uint64, error) {
	status, err := a.c.Status(ctx)
	return status.RestoreAuthority, status.Epoch, err
}

// AuthorityRecords reads every access revocation record.
func (a *API) AuthorityRecords(ctx context.Context) ([]controlplane.AuthorityRecord, error) {
	records, err := pages(ctx, a.c.ExportAccess)
	if err != nil {
		return nil, err
	}
	out := make([]controlplane.AuthorityRecord, 0, len(records))
	for _, r := range records {
		out = append(out, controlplane.AuthorityRecord{
			AccessRecord: controlplane.AccessRecord{ID: r.ID, Kind: r.Kind, Organization: r.Organization, Objects: r.Objects},
			RecordedAt:   time.UnixMilli(r.RecordedAt), Epoch: r.Epoch, Seq: r.Seq, OnReplica: r.OnReplica, Degraded: r.Degraded})
	}
	return out, nil
}

// AuthoritySubjects reads every revocation subject.
func (a *API) AuthoritySubjects(ctx context.Context) ([]string, error) {
	subjects, err := pages(ctx, a.c.ExportSubjects)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, s.Subject)
	}
	return out, nil
}

// AuthorityStores reads every store.
func (a *API) AuthorityStores(ctx context.Context) ([]controlplane.AuthorityStore, error) {
	stores, err := pages(ctx, a.c.ExportStores)
	if err != nil {
		return nil, err
	}
	out := make([]controlplane.AuthorityStore, 0, len(stores))
	for _, s := range stores {
		out = append(out, controlplane.AuthorityStore{ID: s.ID, Volume: s.Volume, Incarnation: s.Incarnation, Sealed: s.Sealed})
	}
	return out, nil
}

// AuthorityAnnouncement is what the promotion to the service's epoch
// announced.
func (a *API) AuthorityAnnouncement(ctx context.Context) (controlplane.FailoverAnnouncement, error) {
	got, err := a.c.Announcement(ctx)
	return controlplane.FailoverAnnouncement{Epoch: got.Epoch, Degraded: got.Degraded, WindowFrom: got.LastContact, WindowTo: got.Failover,
		Blanket: got.Blanket}, err
}

// ImportSubjects begins, in the authority, the subjects it lacks.
func (a *API) ImportSubjects(ctx context.Context, subjects []string) error {
	_, err := a.c.ImportSubjects(ctx, subjects)
	return err
}

// ImportScopes begins, in the authority, the subjects it lacks, each in
// the scope PostgreSQL names for it (controlplane.ScopedImporter).
func (a *API) ImportScopes(ctx context.Context, scopes []controlplane.RevocationScope) error {
	subjects := make([]string, len(scopes))
	named := make([]restoreauthority.Scope, len(scopes))
	for i, s := range scopes {
		subjects[i] = s.Subject
		named[i] = restoreauthority.Scope{Subject: s.Subject, Stores: s.Stores}
	}
	_, err := a.c.importSubjects(ctx, subjects, named)
	return err
}
