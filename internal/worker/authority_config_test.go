//go:build linux && cgo

package worker

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

const workerBase = `{"version":1,"host_id":"host","boot_timeout":"30s","boot_lease":"2m","poll_interval":"1s","attempt_timeout":"45s"`

func authoritySection(socket, restoreID, keyID string) string {
	return `"authority":{"socket":"` + socket + `","restore_authority_id":"` + restoreID + `","key_authority_id":"` + keyID + `"}`
}

// The worker never opens the authorities' directories: a configuration that
// still names them, or their replica, is refused by name, so that no worker
// writes behind the authority service (ADR 006 §5).
func TestWorkerRefusesTheOldAuthoritySections(t *testing.T) {
	restoreID, keyID := "restoreauth_"+strings.Repeat("a", 32), "keyauth_"+strings.Repeat("b", 32)
	authority := authoritySection("/run/agentcapsule-authority/worker.sock", restoreID, keyID)
	for name, section := range map[string]string{
		"key_authority":     `"key_authority":{"root":"/var/lib/agentcapsule-key-authority","identity":"` + keyID + `"}`,
		"restore_authority": `"restore_authority":{"root":"/var/lib/agentcapsule-restore-authority","identity":"` + restoreID + `"}`,
		"authority_replica": `"authority_replica":{"address":"standby.internal:7443","certificate":"/etc/agentcapsule/authority-primary.crt",` +
			`"key":"/etc/agentcapsule/authority-primary.key","replica_certificate":"/etc/agentcapsule/authority-replica.crt"}`,
		"null section": `"key_authority":null`,
	} {
		for _, with := range []string{"", "," + authority} {
			c, err := decodeServiceConfig(strings.NewReader(workerBase + "," + section + with + "}"))
			if err != nil {
				t.Fatal(name, "was not read, so not refused by name:", err)
			}
			if _, _, _, err = c.Settings(); !errors.Is(err, ErrAuthorityServiceRequired) || AuthorityFailure(err) != "authority_service_required" {
				t.Fatal(name, "accepted:", err)
			}
		}
	}
	// The authority section: the worker socket and both identities.
	c, err := decodeServiceConfig(strings.NewReader(workerBase + "," + authority + `,"provisioning":{"first_uid":62000,"last_uid":62009}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = c.Settings(); err != nil {
		t.Fatal(err)
	}
	if client, err := c.OpenAuthority(); err != nil || client == nil || client.Identity() != restoreID || client.KeyAuthorityIdentity() != keyID {
		t.Fatal("authority client", err)
	}
	for name, section := range map[string]string{
		"relative socket":      authoritySection("run/worker.sock", restoreID, keyID),
		"unclean socket":       authoritySection("/run/agentcapsule-authority/../worker.sock", restoreID, keyID),
		"socket path too long": authoritySection("/run/"+strings.Repeat("a", 100)+"/worker.sock", restoreID, keyID),
		"restore identity":     authoritySection("/run/agentcapsule-authority/worker.sock", "restoreauth_short", keyID),
		"key identity":         authoritySection("/run/agentcapsule-authority/worker.sock", restoreID, restoreID),
		"identities missing":   `"authority":{"socket":"/run/agentcapsule-authority/worker.sock"}`,
		"provisioning alone":   `"provisioning":{"first_uid":62000,"last_uid":62009}`,
	} {
		c, err := decodeServiceConfig(strings.NewReader(workerBase + "," + section + "}"))
		if err != nil {
			t.Fatal(name, err)
		}
		if _, _, _, err = c.Settings(); err == nil || errors.Is(err, ErrAuthorityServiceRequired) {
			t.Fatal(name, "accepted:", err)
		}
	}
	// Without the section: the laboratory host, without authorities.
	c, err = decodeServiceConfig(strings.NewReader(workerBase + "}"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = c.Settings(); err != nil {
		t.Fatal(err)
	}
	if client, err := c.OpenAuthority(); client != nil || err != nil {
		t.Fatal("an authority client without the section", err)
	}
}

// The worker nowhere opens or initializes an authority directory: only the
// authority service and the administrator's commands do.
func TestWorkerNeverOpensTheAuthorities(t *testing.T) {
	opens := map[string]map[string]bool{
		"restoreauthority": {"Open": true, "Initialize": true, "OpenReplica": true, "InitializeReplica": true, "Promote": true},
		"keyauthority":     {"Open": true, "Initialize": true},
	}
	var files []string
	for _, pattern := range []string{"*.go", "../../cmd/agentcapsule-worker/*.go"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := s.X.(*ast.Ident); ok && opens[x.Name][s.Sel.Name] {
					t.Errorf("%s opens an authority directory: %s.%s", path, x.Name, s.Sel.Name)
				}
			}
			return true
		})
	}
	if checked < 10 {
		t.Fatal("too few files checked", checked)
	}
}

// The worker waits for a service that does not answer yet, refuses one that
// holds other authorities, and checks its runtime and archive roots against
// the directories the service gives.
func TestWorkerChecksItsRootsAgainstTheService(t *testing.T) {
	dir := t.TempDir()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(t.Context(), filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	service := startAuthorityService(t, keys, catalog)
	open := func(restoreID, keyID string) *ServiceConfig {
		c, err := decodeServiceConfig(strings.NewReader(workerBase + "," + authoritySection(service.socket, restoreID, keyID) + "}"))
		if err != nil {
			t.Fatal(err)
		}
		return &c
	}
	c := open(catalog.Identity(), keys.Identity())
	client, err := c.OpenAuthority()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	runtimeRoot := filepath.Join(dir, "runtime")
	if err = WaitForAuthority(t.Context(), client, runtimeRoot, nil); err != nil {
		t.Fatal(err)
	}
	for _, inside := range []string{filepath.Join(dir, "keys", "runtime"), filepath.Join(dir, "restore", "runtime"), dir} {
		if err = WaitForAuthority(t.Context(), client, inside, nil); AuthorityFailure(err) != "authority_domain_overlap" {
			t.Fatal("a runtime root overlapping an authority", inside, err)
		}
	}
	if client.SeparateFrom(filepath.Join(dir, "archives")) != nil || client.SeparateFrom(filepath.Join(dir, "restore", "archives")) == nil {
		t.Fatal("archive root separation")
	}
	// The worker's constructor checks its runtime root the same way, before
	// anything else (here, the missing database).
	if _, err = NewPlacementsWithAuthority(nil, "host", "worker", time.Minute, runtime.FirecrackerOptions{Root: filepath.Join(dir, "keys", "runtime")}, client, client); !errors.Is(err, restoreauthority.ErrInput) {
		t.Fatal("a runtime root inside the key authority", err)
	}
	if _, err = NewPlacementsWithAuthority(nil, "host", "worker", time.Minute, runtime.FirecrackerOptions{Root: runtimeRoot}, client, client); !errors.Is(err, controlplane.ErrPlacement) {
		t.Fatal("a separated runtime root", err)
	}
	// Another installation's authorities: refused at once, never waited for.
	other, err := open("restoreauth_"+strings.Repeat("0", 32), keys.Identity()).OpenAuthority()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = WaitForAuthority(within(t, 10*time.Second), other, runtimeRoot, func(error) { t.Error("waited for another installation") }); AuthorityFailure(err) != "authority_identity_mismatch" {
		t.Fatal("another installation's service", err)
	}
	// A service that does not answer yet is waited for.
	service.stop(t)
	var waits atomic.Int32
	if err = WaitForAuthority(within(t, 300*time.Millisecond), client, runtimeRoot, func(error) { waits.Add(1) }); AuthorityFailure(err) != "authority_service_unavailable" || waits.Load() == 0 {
		t.Fatal("the worker did not wait for its service", err, waits.Load())
	}
	var restarted sync.WaitGroup
	restarted.Go(func() {
		time.Sleep(300 * time.Millisecond)
		service.restart(t)
	})
	if err = WaitForAuthority(within(t, 30*time.Second), client, runtimeRoot, nil); err != nil {
		t.Fatal("the worker did not reach its restarted service", err)
	}
	restarted.Wait()
}

func within(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	t.Cleanup(cancel)
	return ctx
}

// cutLink is an in-memory link to the replica that can be cut.
type cutLink struct {
	target authoritylog.Link
	down   atomic.Bool
}

func (l *cutLink) Sync(ctx context.Context, r authoritylog.Request) (authoritylog.Position, error) {
	if l.down.Load() {
		return authoritylog.Position{}, errors.New("standby unreachable")
	}
	return l.target.Sync(ctx, r)
}

// Degraded mode belongs to the authority service: a worker that restarts
// during it finds it going on, and its deliveries' outcomes still record at
// once. Before the service, the restarted worker reopened the authorities
// and ran nothing until the standby answered (ADR 005, finding 2).
func TestWorkerRestartKeepsDegradedMode(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	keys, err := keyauthority.Initialize(ctx, filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(ctx, filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	_, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = catalog.Snapshot(ctx, keys, recipient, filepath.Join(dir, "snapshot.sqlite")); err != nil {
		t.Fatal(err)
	}
	replica, err := restoreauthority.InitializeReplica(ctx, filepath.Join(dir, "replica"), filepath.Join(dir, "snapshot.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { replica.Close() })
	link := &cutLink{target: replica}
	if err = authorityservice.LinkTo(ctx, catalog, keys, link, authoritylog.MinDegradedAfter); err != nil {
		t.Fatal(err)
	}
	service := startAuthorityService(t, keys, catalog)
	config, err := decodeServiceConfig(strings.NewReader(workerBase + "," + authoritySection(service.socket, catalog.Identity(), keys.Identity()) + "}"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(dir, "runtime")
	start := func() restoreauthority.Authority {
		t.Helper()
		client, err := config.OpenAuthority()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		if err = WaitForAuthority(within(t, 5*time.Second), client, runtimeRoot, func(err error) { t.Error("the worker waited", err) }); err != nil {
			t.Fatal(err)
		}
		return client
	}
	first := start()
	b, err := first.Register(ctx, "agt_"+strings.Repeat("a", 32), "vol_"+strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	// The standby goes away: a write waits for it, then after
	// degraded_after degraded mode begins.
	link.down.Store(true)
	if err = first.RecordOutcome(within(t, 500*time.Millisecond), b, restoreauthority.Outcome{ID: "event-0"}); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("a write returned without the standby, before degraded mode", err)
	}
	degraded := func(a restoreauthority.Authority) bool {
		status, err := a.(interface {
			Status(context.Context) (authorityservice.Status, error)
		}).Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return status.Mode == restoreauthority.ModeDegraded && status.DegradedSince > 0
	}
	deadline := time.Now().Add(30 * time.Second)
	for !degraded(first) {
		if time.Now().After(deadline) {
			t.Fatal("no degraded mode")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err = first.RecordOutcome(within(t, 2*time.Second), b, restoreauthority.Outcome{ID: "event-1"}); err != nil {
		t.Fatal("an outcome waited in degraded mode", err)
	}
	// The worker restarts: a new process, a new client.
	first.(interface{ Close() error }).Close()
	second := start()
	if !degraded(second) {
		t.Fatal("a worker restart ended degraded mode")
	}
	if err = second.RecordOutcome(within(t, 2*time.Second), b, restoreauthority.Outcome{ID: "event-2"}); err != nil {
		t.Fatal("the restarted worker waited for the standby", err)
	}
	if _, err = second.ReserveIncarnation(within(t, 500*time.Millisecond), b, "restore"); !errors.Is(err, restoreauthority.ErrWaitsForReplica) {
		t.Fatal("a reservation ran in degraded mode", err)
	}
	// The standby returns: degraded mode ends.
	link.down.Store(false)
	if _, err = second.ReserveIncarnation(ctx, b, "restore"); err != nil {
		t.Fatal(err)
	}
	if degraded(second) {
		t.Fatal("degraded mode did not end")
	}
}
