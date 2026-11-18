//go:build linux && cgo

package authorityclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// The socket gives the role, and the peer's account is checked at each
// accept: the worker socket admits root only, the API socket the API's
// account and root; the API socket serves no worker operation.
func TestSocketRoleFollowsPeerCredentials(t *testing.T) {
	uid := uint32(os.Getuid())
	if uid == 0 {
		t.Skip("needs an account other than root")
	}
	keys, catalog := authorities(t, t.TempDir())
	// Production's worker socket: root only. This test's account is the API's.
	l := serve(t, keys, catalog, peers(0, uid))
	worker := l.client(t)
	if _, err := worker.Status(t.Context()); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("a non-root peer reached the worker socket", err)
	}
	if _, err := worker.Lookup(t.Context(), "store-a"); !errors.Is(err, restoreauthority.ErrUnavailable) || errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("a non-root peer ran a worker operation", err)
	}
	if !strings.Contains(l.scrape(t), `agentcapsule_authority_service_refused_peers_total{socket="worker"} 2`) {
		t.Fatal("the refused peers are not counted")
	}
	api := l.clientOf(t, l.api, svc.RoleAPI, catalog.Identity(), keys.Identity())
	status, err := api.Status(t.Context())
	if err != nil || status.RestoreAuthority != catalog.Identity() || status.KeyAuthority != keys.Identity() || status.Mode != restoreauthority.ModeStandalone {
		t.Fatal(status, err)
	}
	if _, err = api.Lookup(t.Context(), "store-a"); !errors.Is(err, svc.ErrRole) {
		t.Fatal("the API socket ran a worker operation", err)
	}
	if err = api.HoldBinding(t.Context(), restoreauthority.Binding{Store: "s", Volume: "v", Incarnation: 1}, func(context.Context) error {
		t.Error("the API socket granted a hold")
		return nil
	}); !errors.Is(err, svc.ErrRole) {
		t.Fatal(err)
	}
	// A worker's hello on the API socket.
	impostor := l.clientOf(t, l.api, svc.RoleWorker, catalog.Identity(), keys.Identity())
	if _, err = impostor.Status(t.Context()); !errors.Is(err, svc.ErrRole) {
		t.Fatal("the API socket accepted a worker", err)
	}
	// Another account on the API socket.
	other := serve(t, keys, catalog, peers(0, uid+1))
	if _, err = other.clientOf(t, other.api, svc.RoleAPI, catalog.Identity(), keys.Identity()).Status(t.Context()); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("another account reached the API socket", err)
	}
	if !strings.Contains(other.scrape(t), `agentcapsule_authority_service_refused_peers_total{socket="api"} 1`) {
		t.Fatal("the refused peer is not counted")
	}
}

// A client never talks to another installation's authorities, nor to a
// service of another protocol.
func TestHelloRefusesAnotherInstallation(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	otherRestore, otherKeys := "restoreauth_"+strings.Repeat("0", 32), "keyauth_"+strings.Repeat("0", 32)
	for name, c := range map[string]*Client{
		"restore authority": l.clientOf(t, l.worker, svc.RoleWorker, otherRestore, keys.Identity()),
		"key authority":     l.clientOf(t, l.worker, svc.RoleWorker, catalog.Identity(), otherKeys),
	} {
		if _, err := c.Lookup(t.Context(), "store-a"); !errors.Is(err, svc.ErrIdentity) || !errors.Is(err, restoreauthority.ErrUnavailable) {
			t.Fatal("a client talked to another", name, err)
		}
	}
	for _, version := range []int{0, svc.Protocol + 1} {
		conn, err := net.Dial("unix", l.worker)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err = authoritylog.WriteFrame(conn, svc.Hello{Protocol: version, Role: svc.RoleWorker, RestoreAuthority: catalog.Identity(), KeyAuthority: keys.Identity()}); err != nil {
			t.Fatal(err)
		}
		var r svc.Response
		if err = authoritylog.ReadFrame(conn, &r, svc.MaxResponse); err != nil || r.Error != svc.CodeProtocol {
			t.Fatal("protocol", version, "accepted", r, err)
		}
		if err = authoritylog.ReadFrame(conn, &r, svc.MaxResponse); !errors.Is(err, io.EOF) {
			t.Fatal("the connection outlived a refused hello", err)
		}
	}
	if _, err := l.client(t).Lookup(t.Context(), "missing"); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal(err)
	}
}

// recorder relays one connection to the service and keeps what each side
// sent.
type recorder struct {
	mu                     sync.Mutex
	fromService, toService bytes.Buffer
}

func (r *recorder) relay(t *testing.T, path, target string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("unix", target)
			if err != nil {
				in.Close()
				return
			}
			pump := func(dst, src net.Conn, keep *bytes.Buffer) {
				buf := make([]byte, 4096)
				for {
					n, err := src.Read(buf)
					if n > 0 {
						r.mu.Lock()
						keep.Write(buf[:n])
						r.mu.Unlock()
						dst.Write(buf[:n])
					}
					if err != nil {
						dst.Close()
						return
					}
				}
			}
			go pump(out, in, &r.toService)
			go pump(in, out, &r.fromService)
		}
	}()
}

// Volume keys reach the worker as 32 raw bytes after the held frame, never
// inside JSON.
func TestKeyBytesNeverTravelInJSON(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	b, err := l.client(t).Register(t.Context(), agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.client(t).Ensure(t.Context(), agent, volume); err != nil {
		t.Fatal(err)
	}
	var rec recorder
	relay := filepath.Join(socketDir(t), "relay.sock")
	rec.relay(t, relay, l.worker)
	c := l.clientOf(t, relay, svc.RoleWorker, catalog.Identity(), keys.Identity())
	var key []byte
	if err = c.HoldKey(t.Context(), b, func(_ context.Context, k []byte) error { key = bytes.Clone(k); return nil }); err != nil {
		t.Fatal(err)
	}
	if err = c.HoldKey(t.Context(), b, func(_ context.Context, k []byte) error {
		if !bytes.Equal(k, key) {
			t.Error("two holds carried different keys")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("no key held")
	}
	encodings := [][]byte{key, []byte(base64.StdEncoding.EncodeToString(key)), []byte(base64.RawStdEncoding.EncodeToString(key)),
		[]byte(base64.URLEncoding.EncodeToString(key)), []byte(hex.EncodeToString(key))}
	rec.mu.Lock()
	fromService, toService := bytes.Clone(rec.fromService.Bytes()), bytes.Clone(rec.toService.Bytes())
	rec.mu.Unlock()
	if bytes.Count(fromService, key) != 2 {
		t.Fatal("the key did not travel once per hold", bytes.Count(fromService, key))
	}
	for _, e := range encodings {
		if bytes.Contains(toService, e) {
			t.Fatal("the client sent the key back")
		}
	}
	// Walk the service's stream frame by frame: the key follows each held
	// frame of a key hold, as raw bytes, and no frame holds it.
	stream, keysSeen := bytes.NewReader(fromService), 0
	for stream.Len() > 0 {
		var size uint32
		if err = binary.Read(stream, binary.BigEndian, &size); err != nil {
			t.Fatal(err)
		}
		frame := make([]byte, size)
		if _, err = io.ReadFull(stream, frame); err != nil {
			t.Fatal(err)
		}
		for _, e := range encodings {
			if bytes.Contains(frame, e) {
				t.Fatal("a JSON frame carried the key:", string(frame))
			}
		}
		var r svc.Response
		if err = json.Unmarshal(frame, &r); err != nil {
			t.Fatal(err)
		}
		if r.Held != nil {
			raw := make([]byte, svc.KeySize)
			if _, err = io.ReadFull(stream, raw); err != nil || !bytes.Equal(raw, key) {
				t.Fatal("the key did not follow its held frame", err)
			}
			keysSeen++
		}
	}
	if keysSeen != 2 {
		t.Fatal(keysSeen)
	}
}

// Each code of the service comes back as today's sentinel errors, so that
// every errors.Is of the worker keeps working; an error that carries an
// outage is an outage, never a stale binding; a connection that fails or
// ends is an outage.
func TestEveryErrorKeepsItsSentinel(t *testing.T) {
	ra, ka := restoreauthority.ErrUnavailable, keyauthority.ErrUnavailable
	want := map[string][]error{
		svc.CodeInput:           {restoreauthority.ErrInput},
		svc.CodeUnavailable:     {ra},
		svc.CodeConflict:        {restoreauthority.ErrConflict},
		svc.CodeStale:           {restoreauthority.ErrStale},
		svc.CodeRevoked:         {restoreauthority.ErrRevoked},
		svc.CodeSealed:          {restoreauthority.ErrSealed},
		svc.CodeHistory:         {restoreauthority.ErrHistory},
		svc.CodeNotDeclared:     {restoreauthority.ErrNotDeclared},
		svc.CodeNotSealed:       {restoreauthority.ErrNotSealed},
		svc.CodeWaitsForReplica: {ra, restoreauthority.ErrWaitsForReplica},
		svc.CodeReplicaRequired: {ra, restoreauthority.ErrReplicaRequired},
		svc.CodeNotArmed:        {restoreauthority.ErrNotArmed},
		svc.CodeDiverged:        {ra, restoreauthority.ErrDiverged},
		svc.CodeKeyUnavailable:  {ka},
		svc.CodeKeyRevoked:      {keyauthority.ErrRevoked},
		svc.CodeKeyConflict:     {keyauthority.ErrConflict},
		svc.CodeKeyInput:        {keyauthority.ErrInput},
		svc.CodeHoldExpired:     {ra, svc.ErrHoldExpired},
		svc.CodeRole:            {ra, svc.ErrRole},
		svc.CodeProtocol:        {ra, svc.ErrProtocol},
		svc.CodeIdentity:        {ra, svc.ErrIdentity},
	}
	if len(want) != len(svc.Codes()) {
		t.Fatal("a code without its sentinels")
	}
	refusals := []error{restoreauthority.ErrStale, restoreauthority.ErrSealed, restoreauthority.ErrRevoked, restoreauthority.ErrConflict, restoreauthority.ErrNotSealed}
	for _, code := range svc.Codes() {
		err := svc.ErrorOf(code)
		for _, sentinel := range want[code] {
			if !errors.Is(err, sentinel) {
				t.Fatal(code, "lost", sentinel)
			}
			// The service's own error of that kind travels as this code.
			if got := svc.Code(errors.Join(want[code]...)); got != code {
				t.Fatal(code, "sent as", got)
			}
		}
		for _, r := range refusals {
			if errors.Is(err, r) && !errors.Is(want[code][0], r) {
				t.Fatal(code, "became", r)
			}
		}
	}
	if svc.ErrorOf("from_a_newer_service").(*svc.Error).Code != svc.CodeProtocol {
		t.Fatal("an unknown code is not a protocol error")
	}
	// The errors the authorities return, as they return them.
	for err, code := range map[error]string{
		errors.Join(ra, restoreauthority.ErrWaitsForReplica, context.DeadlineExceeded): svc.CodeWaitsForReplica,
		errors.Join(ra, restoreauthority.ErrReplicaRequired):                           svc.CodeReplicaRequired,
		errors.Join(ra, authoritylog.ErrDiverged):                                      svc.CodeDiverged,
		errors.Join(ra, restoreauthority.ErrInput):                                     svc.CodeUnavailable,
		errors.Join(ra, restoreauthority.ErrStale):                                     svc.CodeUnavailable,
		context.DeadlineExceeded:                                                       svc.CodeUnavailable,
		errors.New("disk I/O error"):                                                   svc.CodeUnavailable,
		errors.Join(restoreauthority.ErrInput, errors.New("argument")):                 svc.CodeInput,
	} {
		if got := svc.Code(err); got != code {
			t.Fatal(err, "sent as", got, "not", code)
		}
	}

	// Through the socket: a stale binding stays stale.
	dir := t.TempDir()
	keys, catalog := authorities(t, dir)
	l := serve(t, keys, catalog)
	c := l.client(t)
	b, err := c.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	stale := b
	stale.Incarnation = 2
	if err = c.CheckBinding(t.Context(), stale); !errors.Is(err, restoreauthority.ErrStale) || errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal(err)
	}
	if err = c.Ensure(t.Context(), "agt_bad", volume); !errors.Is(err, keyauthority.ErrInput) {
		t.Fatal(err)
	}
	// The service stops: the pooled connection ends, and the next request
	// is an outage, never a stale binding.
	if err = l.stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, check := range []func() error{
		func() error { return c.CheckBinding(t.Context(), stale) },
		func() error { return c.HoldBinding(t.Context(), b, func(context.Context) error { return nil }) },
	} {
		if err = check(); !errors.Is(err, restoreauthority.ErrUnavailable) || errors.Is(err, restoreauthority.ErrStale) {
			t.Fatal("an outage reported as", err)
		}
	}
	// A new service on the same socket: the client dials again.
	keys, catalog = reopen(t, dir, keys, catalog)
	serveAt(t, filepath.Dir(l.worker), keys, catalog)
	if err = c.CheckBinding(t.Context(), b); err != nil {
		t.Fatal(err)
	}
}
