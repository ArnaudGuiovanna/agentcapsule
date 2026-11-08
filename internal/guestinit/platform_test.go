//go:build linux

package guestinit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// A deliberately small independent test harness, not the product business
// implementation. Its persistent intent and stable key exercise the new bridge
// across a real process restart. Network calls occur outside SQLite callbacks.
func TestPlatformHarnessChild(t *testing.T) {
	if os.Args[len(os.Args)-1] != "platform-child" {
		return
	}
	config := os.NewFile(3, "config")
	b, err := ReadHarnessBoot(config)
	config.Close()
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(4, "control")
	listener, err := net.FileListener(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	path := filepath.Join(b.DataDirectory, "harness.db")
	store, err := harnessstore.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.Apply(ctx, harnessstore.Event{ID: "intent", Subjects: []string{"agent/" + b.Identity.AgentID}, Body: []byte("request")}, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
		if _, err := tx.ExecContext(ctx, "CREATE TABLE outgoing(key TEXT PRIMARY KEY,result BLOB)"); err != nil {
			return nil, err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO outgoing(key) VALUES('stable-business-key')")
		return []byte(`{}`), err
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var key string
	err = db.QueryRowContext(ctx, "SELECT key FROM outgoing").Scan(&key)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	client, err := capsuleprotocol.NewLocalPlatformClient(b.Identity, b.PlatformSocket)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.Submit(ctx, key, capsuleprotocol.Submission{RecipientAgentID: "b", MandateID: "fixture-grant"})
	if err == nil {
		body, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.Apply(ctx, harnessstore.Event{ID: "outcome", Subjects: []string{"agent/" + b.Identity.AgentID}, Body: body}, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
			_, err := tx.ExecContext(ctx, "UPDATE outgoing SET result=? WHERE key=?", body, key)
			return body, err
		})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		var remote *capsuleprotocol.PlatformError
		if !errors.As(err, &remote) || remote.Code != "commit_unknown" {
			t.Fatal(err)
		}
	}
	server, err := capsuleprotocol.NewLocalServer(b.Identity, b.PreviousShutdown, store, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) { return []byte(`{}`), nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = server.ServeLocal(ctx, listener.(*net.UnixListener), b.SupervisorUID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// Remote ledger fixture: commits one business identity, then loses its first
// receipt. Actual PostgreSQL authorization/idempotence is tested separately.
type bridgeLedger struct {
	mu      sync.Mutex
	key     string
	effects int
	current atomic.Uint64
}
type bridgeAPI struct {
	ledger     *bridgeLedger
	generation uint64
}

func (a bridgeAPI) Validate(context.Context) error {
	if a.ledger.current.Load() != a.generation {
		return &capsuleprotocol.PlatformError{Code: "unauthorized"}
	}
	return nil
}
func (a bridgeAPI) Submit(ctx context.Context, key string, in capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error) {
	if err := a.Validate(ctx); err != nil {
		return capsuleprotocol.PlatformReceipt{}, err
	}
	a.ledger.mu.Lock()
	defer a.ledger.mu.Unlock()
	if a.ledger.key == "" {
		a.ledger.key = key
		a.ledger.effects++
		return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "commit_unknown"}
	}
	if key != a.ledger.key {
		return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "conflict"}
	}
	return capsuleprotocol.PlatformReceipt{RequestID: "request-one", State: "PENDING_APPROVAL", Replayed: true}, nil
}
func (a bridgeAPI) Reply(context.Context, string, string, capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error) {
	return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "invalid"}
}
func (a bridgeAPI) Search(context.Context, []string) ([]string, error) {
	return nil, &capsuleprotocol.PlatformError{Code: "invalid"}
}

func TestIndependentHarnessPlatformBridgeReplayAndRetirement(t *testing.T) {
	root, err := os.MkdirTemp("", "acp-bridge-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err = os.Chmod(root, 0711); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	if err = os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid, gid = 1000, 1000
	}
	if err = os.Chown(data, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "harness-test")
	out, err := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(out, in)
	in.Close()
	closeErr := out.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	ledger := &bridgeLedger{}
	var old *capsuleprotocol.PlatformClient
	var oldRemote *capsuleprotocol.PlatformClient
	var active *Process
	defer func() {
		if active != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = active.Stop(ctx)
		}
	}()
	for generation := uint64(1); generation <= 2; generation++ {
		ledger.current.Store(generation)
		id := capsuleprotocol.Identity{Incarnation: 1, AgentID: "a", Generation: generation, VMID: map[uint64]string{1: "0123456789abcdef", 2: "0123456789abcdee"}[generation]}
		host, guest, err := capsuleprotocol.NewBootCredentials(id, time.Hour, true)
		if err != nil {
			t.Fatal(err)
		}
		handler, err := capsuleprotocol.NewPlatformHandler(id, bridgeAPI{ledger: ledger, generation: generation})
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- capsuleprotocol.ServeAuthenticated(ctx, l, *host.Platform, handler) }()
		defer func() { cancel(); <-done }()
		remote, err := capsuleprotocol.NewPlatformClient(*guest.Platform, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
		})
		if err != nil {
			t.Fatal(err)
		}
		opts := ProcessOptions{Boot: HarnessBoot{Protocol: capsuleprotocol.Version, PreviousShutdown: capsuleprotocol.ShutdownClean, Identity: id, DataDirectory: data, SupervisorUID: uint32(os.Geteuid()), PlatformSocket: filepath.Join(root, "platform.sock")}, Entrypoint: []string{binary, "-test.run=^TestPlatformHarnessChild$", "--", "platform-child"}, SocketPath: filepath.Join(root, "control.sock"), UID: uid, GID: gid, Platform: remote}
		ready, stop := context.WithTimeout(t.Context(), 15*time.Second)
		active, err = StartHarness(t.Context(), ready, opts)
		stop()
		if err != nil {
			t.Fatal("platform child startup", err)
		}
		if generation == 2 {
			err = old.Health(t.Context())
			if os.Geteuid() == int(uid) {
				if !errors.Is(err, capsuleprotocol.ErrIdentity) {
					t.Fatal("old Unix identity accepted by new bridge", err)
				}
			} else {
				var denied *capsuleprotocol.PlatformError
				if !errors.As(err, &denied) || denied.Code != "unauthorized" {
					t.Fatal("supervisor impersonated harness Unix peer", err)
				}
			}
			var denied *capsuleprotocol.PlatformError
			if err = oldRemote.Health(t.Context()); !errors.As(err, &denied) || denied.Code != "unauthorized" {
				t.Fatal("old authenticated boot retained API authority", err)
			}
		}
		old, err = capsuleprotocol.NewLocalPlatformClient(id, opts.Boot.PlatformSocket)
		if err != nil {
			t.Fatal(err)
		}
		oldRemote = remote
		stopCtx, stop := context.WithTimeout(t.Context(), 5*time.Second)
		err = active.Stop(stopCtx)
		stop()
		if err != nil {
			t.Fatal(err)
		}
		active = nil
		if _, err = os.Stat(opts.Boot.PlatformSocket); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("bridge survived harness exit", err)
		}
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(data, "harness.db")+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		var encoded []byte
		err = db.QueryRowContext(t.Context(), "SELECT result FROM outgoing").Scan(&encoded)
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
		if generation == 1 && encoded != nil {
			t.Fatal("unknown outcome acknowledged")
		}
		if generation == 2 {
			var r capsuleprotocol.PlatformReceipt
			if json.Unmarshal(encoded, &r) != nil || !r.Replayed || r.RequestID != "request-one" {
				t.Fatal("persistent intent did not obtain original result")
			}
		}
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.effects != 1 {
		t.Fatal("new business identity after process restart", ledger.effects)
	}
}

func TestHarnessBridgeRejectsUnsafeBindingAndDirectory(t *testing.T) {
	root := t.TempDir()
	id := capsuleprotocol.Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}
	_, guest, err := capsuleprotocol.NewBootCredentials(id, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := capsuleprotocol.NewPlatformClient(*guest.Platform, func(context.Context) (net.Conn, error) {
		t.Error("startup unexpectedly dialed host")
		return nil, errors.New("not available")
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := ProcessOptions{Boot: HarnessBoot{Protocol: capsuleprotocol.Version, PreviousShutdown: capsuleprotocol.ShutdownClean, Identity: id, DataDirectory: root, PlatformSocket: filepath.Join(root, "platform.sock")}, UID: 1000, GID: 1000, SocketPath: filepath.Join(root, "control.sock"), Platform: remote}
	for _, change := range []func(*ProcessOptions){
		func(o *ProcessOptions) { o.Boot.Identity.Generation++ },
		func(o *ProcessOptions) { o.Boot.Identity.FenceOnly = true },
		func(o *ProcessOptions) { o.Boot.PlatformSocket = o.SocketPath },
		func(o *ProcessOptions) { o.Platform = nil },
	} {
		bad := opts
		change(&bad)
		if b, err := startPlatformBridge(t.Context(), bad); err == nil {
			_ = b.close()
			t.Fatal("unsafe bridge binding")
		}
	}
	if err = os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if b, err := startPlatformBridge(t.Context(), opts); err == nil {
		_ = b.close()
		t.Fatal("replaceable platform listener")
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(opts.Boot.PlatformSocket, []byte("existing path"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := startPlatformBridge(t.Context(), opts); err == nil {
		_ = b.close()
		t.Fatal("existing path overwritten")
	}
	if body, err := os.ReadFile(opts.Boot.PlatformSocket); err != nil || string(body) != "existing path" {
		t.Fatal("existing path removed", err)
	}
}
