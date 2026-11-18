//go:build linux && cgo

package authorityclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// destructionRequiresPermanentSealTest:
// init.then(revoke(0)).expect(safety).then(destroyKey(0).fail()),
// through the service and in process. A revoked but unsealed store's key
// cannot be destroyed: the authorities refuse it themselves, whatever order
// the worker follows (ADR 006 §3). Only the seal, which is permanent, lets
// the destruction run. The same run on armed authorities, where the
// catalogue checks the seal in the transaction that records the
// destruction, is internal/restoreauthority's
// TestDestructionRequiresPermanentSeal.
func TestDestructionRequiresPermanentSeal(t *testing.T) {
	for name, open := range map[string]func(t *testing.T, keys *keyauthority.Files, catalog *restoreauthority.Catalog) implementation{
		"in process": func(t *testing.T, keys *keyauthority.Files, catalog *restoreauthority.Catalog) implementation {
			return restoreauthority.Local{Catalog: catalog, Keys: keys}
		},
		"through the service": func(t *testing.T, keys *keyauthority.Files, catalog *restoreauthority.Catalog) implementation {
			return serve(t, keys, catalog).client(t)
		},
	} {
		t.Run(name, func(t *testing.T) {
			keys, catalog := authorities(t, t.TempDir())
			destructionRequiresPermanentSeal(t, open(t, keys, catalog), keys)
		})
	}
}

func destructionRequiresPermanentSeal(t *testing.T, a implementation, keys *keyauthority.Files) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	keyLives := func() error { return keys.WithKey(ctx, agent, volume, func([]byte) error { return nil }) }
	b, err := a.Register(ctx, agent, volume)
	must(err)
	must(a.Ensure(ctx, agent, volume))
	// revoke(0): begin, fence the store, complete.
	subject := "agent/" + agent
	_, err = a.BeginRevocation(ctx, subject)
	must(err)
	r, err := a.Scan(ctx, b)
	must(err)
	must(a.RecordVerifiedFence(ctx, r))
	must(a.HoldRevocation(ctx, subject, []restoreauthority.Binding{b}, func(context.Context) error { return nil }))
	if ack, sealed, err := a.SubjectBarrier(ctx, b, subject); err != nil || !ack || sealed {
		t.Fatal("revoked store must be acknowledged and not sealed", ack, sealed, err)
	}
	// destroyKey(0).fail(): a refusal, not an outage.
	if err = a.DestroyKey(ctx, b); !errors.Is(err, restoreauthority.ErrNotSealed) || errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("an unsealed store's key was destroyed", err)
	}
	if err = a.Revoke(ctx, agent, volume); !errors.Is(err, keyauthority.ErrInput) {
		t.Fatal("a key was destroyed without its binding", err)
	}
	stale := b
	stale.Incarnation = 2
	if err = a.DestroyKey(ctx, stale); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("a key was destroyed under another binding", err)
	}
	if err = keyLives(); err != nil {
		t.Fatal("a refused destruction took the key", err)
	}
	must(a.HoldKey(ctx, b, func(context.Context, []byte) error { return nil }))
	// permanentlySeal(0), then destroyKey(0).
	must(a.RecordRetiredSeal(ctx, b))
	must(a.DestroyKey(ctx, b))
	if err = keyLives(); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a destroyed key opened", err)
	}
	if err = a.Ensure(ctx, agent, volume); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("a destroyed key came back", err)
	}
	// The seal is permanent: it outlives the key.
	if _, err = a.Lookup(ctx, agent); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal(err)
	}
	if _, err = a.Register(ctx, agent, volume); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal(err)
	}
	if _, err = a.ReserveIncarnation(ctx, b, "restore-after-deletion"); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal(err)
	}
	must(a.DestroyKey(ctx, b))
}

// The worker socket refuses a destruction without a sealed binding: one that
// names no incarnation (input), and one whose store is not sealed
// (not_sealed). The connection goes on, and the key stays. The client does
// not send a destruction without its binding.
func TestServiceRefusesADestructionWithoutASealedBinding(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	c := l.client(t)
	ctx := t.Context()
	b, err := c.Register(ctx, agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	if err = c.Revoke(ctx, agent, volume); !errors.Is(err, keyauthority.ErrInput) {
		t.Fatal("the client destroyed a key without its binding", err)
	}
	if err = c.DestroyKey(ctx, restoreauthority.Binding{Store: agent, Volume: volume}); !errors.Is(err, restoreauthority.ErrInput) {
		t.Fatal("the client destroyed a key without its incarnation", err)
	}
	conn, err := net.Dial("unix", l.worker)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	send := func(op string, args any) svc.Response {
		t.Helper()
		raw, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		if err = authoritylog.WriteFrame(conn, svc.Request{Op: op, TimeoutMS: 5000, Args: raw}); err != nil {
			t.Fatal(err)
		}
		var r svc.Response
		if err = authoritylog.ReadFrame(conn, &r, svc.MaxResponse); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if err = authoritylog.WriteFrame(conn, svc.Hello{Protocol: svc.Protocol, Role: svc.RoleWorker, RestoreAuthority: catalog.Identity(), KeyAuthority: keys.Identity()}); err != nil {
		t.Fatal(err)
	}
	var hello svc.Response
	if err = authoritylog.ReadFrame(conn, &hello, svc.MaxResponse); err != nil || hello.Error != "" {
		t.Fatal("hello", hello, err)
	}
	if r := send(svc.OpDestroyKey, svc.KeyArgs{Agent: agent, Volume: volume}); r.Error != svc.CodeInput {
		t.Fatal("the service destroyed a key without its binding", r)
	}
	whole := svc.KeyArgs{Agent: agent, Volume: volume, Incarnation: b.Incarnation}
	if r := send(svc.OpDestroyKey, whole); r.Error != svc.CodeNotSealed {
		t.Fatal("the service destroyed an unsealed store's key", r)
	}
	if err = keys.WithKey(ctx, agent, volume, func([]byte) error { return nil }); err != nil {
		t.Fatal("a refused destruction took the key", err)
	}
	if r := send(svc.OpRecordSeal, svc.BindingArgs{Binding: b}); r.Error != "" {
		t.Fatal("seal", r)
	}
	if r := send(svc.OpDestroyKey, whole); r.Error != "" {
		t.Fatal("destruction of a sealed store's key", r)
	}
	if err = keys.WithKey(ctx, agent, volume, func([]byte) error { return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("the key outlived its destruction", err)
	}
}
