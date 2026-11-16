//go:build linux && cgo

package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The two implementations of the worker's authorities (ADR 006 §5): in
// process, the tests' double, and through the authority service, as in
// production. The worker's authority tests run against both.
const (
	inProcess      = "in process"
	throughService = "through the service"
)

var authorityImplementations = []string{inProcess, throughService}

// forEachAuthority runs test once per implementation.
func forEachAuthority(t *testing.T, test func(t *testing.T, implementation string)) {
	for _, implementation := range authorityImplementations {
		t.Run(implementation, func(t *testing.T) { test(t, implementation) })
	}
}

// authorityService is a test's authority service: the server of
// internal/authorityservice on a short socket path, run in this process. The
// quiet period is over at start; it has its own tests.
type authorityService struct {
	keys     *keyauthority.Files
	catalog  *restoreauthority.Catalog
	socket   string
	registry *telemetry.Registry
	stopped  func() error
}

func startAuthorityService(t *testing.T, keys *keyauthority.Files, catalog *restoreauthority.Catalog) *authorityService {
	t.Helper()
	dir, err := os.MkdirTemp("", "acw-") // a socket path has at most 107 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := &authorityService{keys: keys, catalog: catalog, socket: filepath.Join(dir, "worker.sock")}
	s.start(t)
	t.Cleanup(func() { s.stop(t) })
	return s
}

func (s *authorityService) start(t *testing.T) {
	t.Helper()
	s.registry = telemetry.NewRegistry()
	server, err := authorityservice.New(t.Context(), authorityservice.Config{Catalog: s.catalog, Keys: s.keys,
		WorkerUID: uint32(os.Getuid()), APIUID: uint32(os.Getuid()) + 1, Started: time.Now().Add(-time.Hour),
		Metrics: authorityservice.NewMetrics(s.registry)})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := authorityservice.Listen(s.socket, 0600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, nil) }()
	s.stopped = sync.OnceValue(func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(30 * time.Second):
			return errors.New("the authority service did not stop")
		}
	})
}

// stop stops the service: its socket closes, and every hold ends.
func (s *authorityService) stop(t *testing.T) {
	t.Helper()
	if err := s.stopped(); err != nil && !errors.Is(err, context.Canceled) {
		t.Error(err)
	}
}

// restart starts a stopped service again, on the authorities opened anew,
// as systemd starts a new process.
func (s *authorityService) restart(t *testing.T) {
	t.Helper()
	s.stop(t)
	s.catalog.Close()
	keys, err := keyauthority.Open(s.keys.Root(), s.keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Open(t.Context(), s.catalog.Root(), s.catalog.Identity(), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	s.keys, s.catalog = keys, catalog
	s.start(t)
}

// client is a worker's client of the service, once it has reached it, as
// the worker's start does (WaitForAuthority): its status gives the
// directories that SeparateFrom checks.
func (s *authorityService) client(t *testing.T) *authorityclient.Client {
	t.Helper()
	c, err := authorityclient.New(s.socket, authorityservice.RoleWorker, s.catalog.Identity(), s.keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err = c.Status(t.Context()); err != nil {
		t.Fatal(err)
	}
	return c
}

// testAuthority is the authorities a test's worker holds: Authority is
// restoreauthority.Local, or the service's client. It counts the keys that
// holds hand out in observed, when set.
type testAuthority struct {
	restoreauthority.Authority
	keys     *keyauthority.Files
	catalog  *restoreauthority.Catalog
	service  *authorityService // nil in process
	observed *observedKeys
}

// openAuthority returns both authorities, in dir, through implementation.
// keys is open; the restore authority is initialized in dir.
func openAuthority(t *testing.T, implementation string, keys *keyauthority.Files, dir string) *testAuthority {
	t.Helper()
	catalog, err := restoreauthority.Initialize(t.Context(), dir, keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	return useAuthority(t, implementation, keys, catalog)
}

// useAuthority serves keys and catalog through implementation.
func useAuthority(t *testing.T, implementation string, keys *keyauthority.Files, catalog *restoreauthority.Catalog) *testAuthority {
	t.Helper()
	a := &testAuthority{keys: keys, catalog: catalog}
	switch implementation {
	case inProcess:
		a.Authority = restoreauthority.Local{Catalog: catalog, Keys: keys}
	case throughService:
		a.service = startAuthorityService(t, keys, catalog)
		a.Authority = a.service.client(t)
	default:
		t.Fatal("unknown implementation", implementation)
	}
	return a
}

// newClient is another worker process's authorities: a new client of the
// same service.
func (a *testAuthority) newClient(t *testing.T) *testAuthority {
	t.Helper()
	if a.service == nil {
		t.Fatal("no service")
	}
	return &testAuthority{Authority: a.service.client(t), keys: a.keys, catalog: a.catalog, service: a.service}
}

// provider is the key authority as the worker creates and destroys keys:
// the same implementation as the restore authority.
func (a *testAuthority) provider() keyauthority.Provider {
	return a.Authority.(keyauthority.Provider)
}

func (a *testAuthority) HoldKey(ctx context.Context, b restoreauthority.Binding, use func(context.Context, []byte) error) error {
	return a.Authority.HoldKey(ctx, b, func(ctx context.Context, key []byte) error {
		if k := a.observed; k != nil {
			k.uses++
			k.borrowed = key
			if k.beforeUse != nil {
				k.beforeUse()
			}
		}
		return use(ctx, key)
	})
}

// Close is an outage of the authorities: the catalogue closes in process;
// the service stops.
func (a *testAuthority) Close() error {
	if a.service != nil {
		if err := a.service.stopped(); !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}
	return a.catalog.Close()
}

// restart ends an outage: the authorities answer again, opened anew.
func (a *testAuthority) restart(t *testing.T) {
	t.Helper()
	if a.service != nil {
		a.service.restart(t)
		a.keys, a.catalog = a.service.keys, a.service.catalog
		return
	}
	a.catalog.Close()
	catalog, err := restoreauthority.Open(t.Context(), a.catalog.Root(), a.catalog.Identity(), a.keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	a.catalog = catalog
	a.Authority = restoreauthority.Local{Catalog: catalog, Keys: a.keys}
}
