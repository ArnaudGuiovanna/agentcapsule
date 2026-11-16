//go:build linux && cgo

package authorityclient

import (
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// The API's client (ADR 006, wave 4) reaches the API socket with the pinned
// identities, and is refused at once, without waiting, by another
// installation's authorities or by the worker's socket.
func TestAPIClientReachesTheAPISocketOnly(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	restoreID, keyID := catalog.Identity(), keys.Identity()
	for name, path := range map[string]string{"relative": "api.sock", "unclean": l.api + "/", "long": "/" + strings.Repeat("s", 100)} {
		if _, err := NewAPI(path, restoreID, keyID); !errors.Is(err, restoreauthority.ErrInput) {
			t.Fatal("a socket path", name, err)
		}
	}
	if _, err := NewAPI(l.api, keyID, restoreID); !errors.Is(err, restoreauthority.ErrInput) {
		t.Fatal("identities swapped", err)
	}
	a := l.apiClient(t)
	status, err := a.Wait(t.Context(), func(err error) { t.Error("waited for a service that answers", err) })
	if err != nil || status.RestoreAuthority != restoreID || status.KeyAuthority != keyID || status.Epoch != 1 ||
		status.Mode != restoreauthority.ModeStandalone || status.Protocol != svc.Protocol {
		t.Fatal(status, err)
	}
	if again, err := a.Status(t.Context()); err != nil || again != status {
		t.Fatal(again, err)
	}
	refused := func(name, path, restoreID, keyID string, want error) {
		t.Helper()
		c, err := NewAPI(path, restoreID, keyID)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err = c.Wait(within(t, 10*time.Second), func(err error) { t.Error("waited for", name, err) }); !errors.Is(err, want) ||
			!errors.Is(err, restoreauthority.ErrUnavailable) {
			t.Fatal(name, err)
		}
	}
	other := "restoreauth_" + strings.Repeat("0", 32)
	refused("another installation's restore authority", l.api, other, keyID, svc.ErrIdentity)
	refused("another installation's key authority", l.api, restoreID, "keyauth_"+strings.Repeat("0", 32), svc.ErrIdentity)
	// This test's account is admitted on both sockets: the worker socket
	// refuses the API's hello for its role.
	refused("the worker socket", l.worker, restoreID, keyID, svc.ErrRole)
}

// The API waits for a service that does not answer yet, and reaches it once
// it starts.
func TestAPIClientWaitsForTheService(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	dir := socketDir(t)
	a, err := NewAPI(filepath.Join(dir, "api.sock"), catalog.Identity(), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var waits atomic.Int32
	if _, err = a.Wait(within(t, 300*time.Millisecond), func(error) { waits.Add(1) }); !errors.Is(err, restoreauthority.ErrUnavailable) || waits.Load() == 0 {
		t.Fatal("the API did not wait for its service", err, waits.Load())
	}
	type answer struct {
		status svc.Status
		err    error
	}
	reached := make(chan answer, 1)
	waits.Store(0)
	ctx := within(t, 30*time.Second)
	go func() {
		s, err := a.Wait(ctx, func(error) { waits.Add(1) })
		reached <- answer{s, err}
	}()
	time.Sleep(300 * time.Millisecond)
	serveAt(t, dir, keys, catalog)
	got := <-reached
	if got.err != nil || got.status.RestoreAuthority != catalog.Identity() || waits.Load() == 0 {
		t.Fatal("the API did not reach its service once it started", got, waits.Load())
	}
}
