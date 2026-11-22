//go:build linux && cgo

package authorityclient

import (
	"context"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// API is the API's client of the authority service: its socket is the
// service's API socket, and it offers only the operations that socket
// serves (docs/adr/006-authority-service.md §2). Wave 4 needs status: the
// API waits for the service at start, and its readiness probe reports the
// service's mode. Wave 5 adds the access revocation records; the daily
// receipt key (wave 6) and the reconciliation (wave 7) add theirs here.
type API struct {
	c *Client
}

// NewAPI returns a client of the service's API socket at path, pinning the
// two authorities' identities. It does not connect: Wait does.
func NewAPI(path, restoreAuthority, keyAuthority string) (*API, error) {
	c, err := New(path, svc.RoleAPI, restoreAuthority, keyAuthority)
	if err != nil {
		return nil, err
	}
	return &API{c: c}, nil
}

// Close closes the idle connections; later requests fail.
func (a *API) Close() error { return a.c.Close() }

// Status asks the service for its state: the identities it holds, its
// epoch and its mode (standalone, synchronous, degraded, waiting).
func (a *API) Status(ctx context.Context) (svc.Status, error) { return a.c.Status(ctx) }

// AppendAccess appends an access revocation record: the service commits it,
// then waits for the replica until ctx's deadline. An error means that the
// record was not committed, or that the answer was lost: the caller commits
// nothing in PostgreSQL, and may append the same record again.
func (a *API) AppendAccess(ctx context.Context, r restoreauthority.AccessRecord) (restoreauthority.AccessReceipt, error) {
	return a.c.AppendAccess(ctx, r)
}

// AccessStatus asks how far the record id has gone: the service's
// on_replica.
func (a *API) AccessStatus(ctx context.Context, id string) (restoreauthority.AccessReceipt, error) {
	return a.c.AccessStatus(ctx, id)
}

// Wait waits until the service answers, as Client.Wait does: another
// installation's authorities, or a socket of another role, are refused at
// once.
func (a *API) Wait(ctx context.Context, waiting func(error)) (svc.Status, error) {
	return a.c.Wait(ctx, waiting)
}

// The API's client is the control plane's access recorder: every revoking
// transaction appends its record through it once it has committed.
var _ controlplane.AccessRecorder = (*API)(nil)

// RecordAccess is AppendAccess, in the control plane's terms.
func (a *API) RecordAccess(ctx context.Context, r controlplane.AccessRecord) (controlplane.AccessReceipt, error) {
	got, err := a.AppendAccess(ctx, restoreauthority.AccessRecord{ID: r.ID, Kind: r.Kind, Organization: r.Organization, Objects: r.Objects})
	return accessReceipt(got), err
}

// AccessProgress is AccessStatus, in the control plane's terms.
func (a *API) AccessProgress(ctx context.Context, id string) (controlplane.AccessReceipt, error) {
	got, err := a.AccessStatus(ctx, id)
	return accessReceipt(got), err
}

func accessReceipt(r restoreauthority.AccessReceipt) controlplane.AccessReceipt {
	return controlplane.AccessReceipt{Known: r.Known, Epoch: r.Epoch, Seq: r.Seq, OnReplica: r.OnReplica, Degraded: r.Degraded}
}
