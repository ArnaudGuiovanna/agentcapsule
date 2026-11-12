//go:build linux

package worker

import (
	"context"
	"errors"
	"net"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/slimlink"
)

// ServiceSLIM routes deliveries between agents through the SLIM bridge
// (INT-04, docs/interop.md). BridgeSocket is where the bridge listens;
// WorkerSocket is where this worker answers the bridge's calls back. Both
// sockets belong to BridgeUID, the bridge's own unprivileged user: the worker
// checks it on every connection, in both directions.
type ServiceSLIM struct {
	BridgeSocket string `json:"bridge_socket"`
	WorkerSocket string `json:"worker_socket"`
	BridgeUID    int    `json:"bridge_uid"`
}

// ErrSLIMConfig: a socket path is not absolute and clean, both are the same,
// or the bridge's user is root or out of range.
var ErrSLIMConfig = errors.New("slim needs absolute, distinct bridge_socket and worker_socket and an unprivileged bridge_uid")

func validSocketPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && len(p) < 100
}

// OpenSLIM returns nil when the host routes deliveries directly over vsock.
// It does not connect: the bridge may start after the worker.
func (c ServiceConfig) OpenSLIM() (*slimlink.Link, net.Listener, error) {
	s := c.SLIM
	if s == nil {
		return nil, nil, nil
	}
	if !validSocketPath(s.BridgeSocket) || !validSocketPath(s.WorkerSocket) || s.BridgeSocket == s.WorkerSocket || s.BridgeUID <= 0 || s.BridgeUID > 1<<31-2 {
		return nil, nil, ErrSLIMConfig
	}
	l, err := slimlink.Listen(s.WorkerSocket, uint32(s.BridgeUID))
	if err != nil {
		return nil, nil, err
	}
	return slimlink.Open(s.BridgeSocket, uint32(s.BridgeUID)), l, nil
}

// EnableSLIM attaches the bridge once, like EnableDirectory. The caller serves
// the link on its listener.
func (w *Placements) EnableSLIM(l *slimlink.Link) error {
	if l == nil || !w.slim.CompareAndSwap(nil, l) {
		return controlplane.ErrConflict
	}
	return nil
}

func (w *Placements) slimName(ctx context.Context, target string) (string, error) {
	tenant, err := w.store.AgentOrganization(ctx, target)
	if err != nil {
		return "", err
	}
	return slimlink.Name(tenant, target)
}

// serveSLIM runs once the target's VM is ready, before a delivery attempt is
// spent: the bridge must answer on the target's SLIM name. An absent bridge or
// node is backpressure, like a VM that cannot boot. Owner instructions do not
// cross SLIM and never wait for it.
func (w *Placements) serveSLIM(ctx context.Context, target string) error {
	link := w.slim.Load()
	if link == nil {
		return nil
	}
	kind, err := w.store.HeadKind(ctx, target)
	if err != nil || kind == "" || kind == "instruction" {
		return err
	}
	name, err := w.slimName(ctx, target)
	if err != nil {
		return err
	}
	return link.Serve(ctx, name)
}

// sendSLIM delivers through the bridge and SLIM. The bridge serving the
// target's name calls back, and the event that crossed SLIM goes to the VM over
// this attempt's control client, still under the caller's scope.
func (w *Placements) sendSLIM(ctx context.Context, link *slimlink.Link, target string, client *capsuleprotocol.Client, event harnessstore.Event) (harnessstore.Receipt, error) {
	name, err := w.slimName(ctx, target)
	if err != nil {
		return harnessstore.Receipt{}, err
	}
	// Normally done before the attempt (serveSLIM); idempotent, and needed if
	// the queue's head changed in between.
	if err = link.Serve(ctx, name); err != nil {
		return harnessstore.Receipt{}, err
	}
	r, err := link.Deliver(ctx, name, slimlink.Event{ID: event.ID, Subjects: event.Subjects, Body: event.Body},
		func(ctx context.Context, e slimlink.Event) (slimlink.Receipt, error) {
			got, err := w.deliverToGuest(ctx, target, client, harnessstore.Event{ID: e.ID, Subjects: e.Subjects, Body: e.Body}, false)
			return slimlink.Receipt{Result: got.Result, Replayed: got.Replayed}, err
		})
	return harnessstore.Receipt{Result: r.Result, Replayed: r.Replayed}, err
}
