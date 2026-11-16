//go:build linux && cgo

package authorityclient

import (
	"context"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
)

// API is the API's client of the authority service: its socket is the
// service's API socket, and it offers only the operations that socket
// serves (docs/adr/006-authority-service.md §2). Wave 4 needs status: the
// API waits for the service at start, and its readiness probe reports the
// service's mode. The access revocation records (wave 5), the daily receipt
// key (wave 6) and the reconciliation (wave 7) add their operations here.
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

// Wait waits until the service answers, as Client.Wait does: another
// installation's authorities, or a socket of another role, are refused at
// once.
func (a *API) Wait(ctx context.Context, waiting func(error)) (svc.Status, error) {
	return a.c.Wait(ctx, waiting)
}
