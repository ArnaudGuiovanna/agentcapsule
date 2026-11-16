//go:build linux && cgo

package authorityclient

import (
	"context"
	"crypto/sha256"
	"errors"
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
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The worker binds an agent's store to the agent's ID, and the key to its
// volume: a key hold names that binding.
var (
	agent  = "agt_" + strings.Repeat("a", 32)
	volume = "vol_" + strings.Repeat("b", 32)
)

func digest(result string) [32]byte { return sha256.Sum256([]byte(result)) }

// authorities initializes both authorities, standalone, in dir.
func authorities(t *testing.T, dir string) (*keyauthority.Files, *restoreauthority.Catalog) {
	t.Helper()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(t.Context(), filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	return keys, catalog
}

// reopen opens both authorities again, as a restarted service would.
func reopen(t *testing.T, dir string, keys *keyauthority.Files, catalog *restoreauthority.Catalog) (*keyauthority.Files, *restoreauthority.Catalog) {
	t.Helper()
	k, err := keyauthority.Open(filepath.Join(dir, "keys"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	c, err := restoreauthority.Open(t.Context(), filepath.Join(dir, "restore"), catalog.Identity(), k.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return k, c
}

// lab is a running authority service.
type lab struct {
	keys     *keyauthority.Files
	catalog  *restoreauthority.Catalog
	registry *telemetry.Registry
	server   *svc.Server
	worker   string // the worker socket's path
	api      string // the API socket's path
	stop     func() error
}

type option func(*svc.Config)

func caps(publish, key time.Duration) option {
	return func(c *svc.Config) { c.PublishCap, c.MaxKeyHold = publish, key }
}

// startedNow makes the quiet period start with the service.
func startedNow(c *svc.Config) { c.Started = time.Now() }

func peers(worker, api uint32) option {
	return func(c *svc.Config) { c.WorkerUID, c.APIUID = worker, api }
}

// socketDir is a short private directory: a socket path has at most 107
// bytes.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "acs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// serve starts the service on keys and catalog, which it now owns. The
// quiet period is over unless an option says otherwise.
func serve(t *testing.T, keys *keyauthority.Files, catalog *restoreauthority.Catalog, options ...option) *lab {
	t.Helper()
	return serveAt(t, socketDir(t), keys, catalog, options...)
}

func serveAt(t *testing.T, dir string, keys *keyauthority.Files, catalog *restoreauthority.Catalog, options ...option) *lab {
	t.Helper()
	l := &lab{keys: keys, catalog: catalog, registry: telemetry.NewRegistry(),
		worker: filepath.Join(dir, "worker.sock"), api: filepath.Join(dir, "api.sock")}
	uid := uint32(os.Getuid())
	config := svc.Config{Catalog: catalog, Keys: keys, WorkerUID: uid, APIUID: uid, Started: time.Now().Add(-time.Hour),
		Metrics: svc.NewMetrics(l.registry)}
	for _, o := range options {
		o(&config)
	}
	var err error
	if l.server, err = svc.New(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	worker, err := svc.Listen(l.worker, 0600)
	if err != nil {
		t.Fatal(err)
	}
	api, err := svc.Listen(l.api, 0660)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.server.Serve(ctx, worker, api) }()
	l.stop = sync.OnceValue(func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(30 * time.Second):
			return errors.New("the service did not stop")
		}
	})
	t.Cleanup(func() {
		if err := l.stop(); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	return l
}

// client is a worker's client.
func (l *lab) client(t *testing.T) *Client {
	t.Helper()
	return l.clientOf(t, l.worker, svc.RoleWorker, l.catalog.Identity(), l.keys.Identity())
}

func (l *lab) clientOf(t *testing.T, path, role, restoreID, keyID string) *Client {
	t.Helper()
	c, err := New(path, role, restoreID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// apiClient is the API's client, on the API socket.
func (l *lab) apiClient(t *testing.T) *API {
	t.Helper()
	a, err := NewAPI(l.api, l.catalog.Identity(), l.keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

// scrape returns the service's metrics, as Prometheus reads them.
func (l *lab) scrape(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if _, err := l.registry.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func within(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	t.Cleanup(cancel)
	return ctx
}

// fenced registers a store and records the fence of its first scan, as a
// boot does after its guest's acknowledgment.
func fenced(t *testing.T, a restoreauthority.Authority, store, vol string) (restoreauthority.Binding, restoreauthority.Receipt) {
	t.Helper()
	b, err := a.Register(t.Context(), store, vol)
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.Scan(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.RecordVerifiedFence(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	return b, r
}

// tap is an in-memory link to the replica that can be cut.
type tap struct {
	mu     sync.Mutex
	target authoritylog.Link
	down   bool
}

func (l *tap) Sync(ctx context.Context, r authoritylog.Request) (authoritylog.Position, error) {
	l.mu.Lock()
	down, target := l.down, l.target
	l.mu.Unlock()
	if down {
		return authoritylog.Position{}, errors.New("standby unreachable")
	}
	return target.Sync(ctx, r)
}

func (l *tap) set(down bool) {
	l.mu.Lock()
	l.down = down
	l.mu.Unlock()
}
