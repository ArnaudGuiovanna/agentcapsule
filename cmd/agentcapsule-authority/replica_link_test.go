//go:build linux && cgo

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// primaryText is a primary's configuration, with extra fields.
func primaryText(keyRoot, keyID, restoreRoot, restoreID, extra string) string {
	return `{"version":2,"role":"primary","key_authority":{"root":"` + keyRoot + `","identity":"` + keyID +
		`"},"restore_authority":{"root":"` + restoreRoot + `","identity":"` + restoreID +
		`"},"worker_socket":"/run/a/worker.sock","api_socket":"/run/a/api.sock","api_uid":990` + extra + `}`
}

func replicaSection(address, certificate, key, replicaCertificate, degradedAfter string) string {
	s := `,"authority_replica":{"address":"` + address + `","certificate":"` + certificate + `","key":"` + key +
		`","replica_certificate":"` + replicaCertificate + `"`
	if degradedAfter != "" {
		s += `,"degraded_after":"` + degradedAfter + `"`
	}
	return s + "}"
}

// serveWorker runs the service on keys and catalog in this process, and
// returns a worker's client of it.
func serveWorker(t *testing.T, keys *keyauthority.Files, catalog *restoreauthority.Catalog) (*authorityclient.Client, func()) {
	t.Helper()
	sockets, err := os.MkdirTemp("", "acs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockets) })
	server, err := authorityservice.New(t.Context(), authorityservice.Config{Catalog: catalog, Keys: keys, WorkerUID: uint32(os.Getuid()),
		APIUID: uint32(os.Getuid()) + 1, Started: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := authorityservice.Listen(filepath.Join(sockets, "worker.sock"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, nil) }()
	client, err := authorityclient.New(filepath.Join(sockets, "worker.sock"), authorityservice.RoleWorker, catalog.Identity(), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	stop := func() {
		client.Close()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}
	return client, stop
}

func writeLinkCertificates(t *testing.T, dir, restoreID, keyID string) {
	t.Helper()
	for _, role := range []string{"primary", "replica"} {
		certificate, key, err := authoritylog.GenerateCertificate(role, restoreID, keyID)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, role+".crt"), certificate, 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, role+".key"), key, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// The shipped examples read as their roles, once the identities are filled
// in.
func TestConfigurationExamplesNameTheirRoles(t *testing.T) {
	fill := strings.NewReplacer("<restoreauth_PUBLIC_IDENTITY>", "restoreauth_"+strings.Repeat("a", 32),
		"<keyauth_PUBLIC_IDENTITY>", "keyauth_"+strings.Repeat("b", 32))
	for file, primary := range map[string]bool{"primary.example.json": true, "replica.example.json": false} {
		text, err := os.ReadFile(filepath.Join("../../runtime/authority", file))
		if err != nil {
			t.Fatal(err)
		}
		c, err := parseConfig([]byte(fill.Replace(string(text))))
		if err != nil || (c.primary != nil) != primary || (c.replica != nil) == primary {
			t.Fatal(file, err)
		}
		if primary && (c.link == nil || c.maxKeyHold != authorityservice.DefaultMaxKeyHold || c.primary.MetricsListen != "127.0.0.1:9466") {
			t.Fatal(file, "read as", c.primary)
		}
	}
}

// The authority_replica section, now the service's: standalone without it,
// refused when it disagrees with the authorities, and synchronous with it,
// so that the worker's writes through the service reach the replica.
func TestAuthorityReplicaConfiguration(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	keyRoot, restoreRoot := filepath.Join(dir, "keys"), filepath.Join(dir, "restore")
	keys, err := keyauthority.Initialize(ctx, keyRoot)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(ctx, restoreRoot, keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	restoreID, keyID := catalog.Identity(), keys.Identity()
	catalog.Close()
	open := func(extra string) (*keyauthority.Files, *restoreauthority.Catalog, string) {
		t.Helper()
		c, err := parseConfig([]byte(primaryText(keyRoot, keyID, restoreRoot, restoreID, extra)))
		if err != nil {
			t.Fatal(err)
		}
		k, a, code := openPrimary(ctx, c)
		if code == "" {
			t.Cleanup(func() { a.Close() })
		}
		return k, a, code
	}
	// Standalone: the explicit default, without disaster protection.
	_, a, code := open("")
	if code != "" {
		t.Fatal(code)
	}
	registry := telemetry.NewRegistry()
	a.ObserveReplication(authoritylog.NewMetrics(registry))
	var out strings.Builder
	registry.WriteTo(&out)
	if !strings.Contains(out.String(), "agentcapsule_authority_replication_enabled 0\n") {
		t.Fatal("standalone mode not reported")
	}
	a.Close()
	writeLinkCertificates(t, dir, restoreID, keyID)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	section := replicaSection(address, filepath.Join(dir, "primary.crt"), filepath.Join(dir, "primary.key"), filepath.Join(dir, "replica.crt"), "")
	if _, _, code = open(section); code != "authority_replica_not_armed" {
		t.Fatal("replica configured for authorities never armed", code)
	}
	// Arm both authorities and build the replica: the service is stopped.
	k, a, code := open("")
	if code != "" {
		t.Fatal(code)
	}
	_, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err = a.Snapshot(ctx, k, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	a.Close()
	replica, err := restoreauthority.InitializeReplica(ctx, filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	server, err := authoritylog.TLSFiles{Certificate: filepath.Join(dir, "replica.crt"), Key: filepath.Join(dir, "replica.key"),
		PeerCertificate: filepath.Join(dir, "primary.crt"), RestoreAuthority: restoreID, KeyAuthority: keyID}.ServerTLS()
	if err != nil {
		t.Fatal(err)
	}
	serving, cancel := context.WithCancel(ctx)
	defer cancel()
	go (&authoritylog.Server{Replica: replica, Config: server}).Serve(serving, listener)
	if _, _, code = open(""); code != "authority_replica_required" {
		t.Fatal("armed authorities opened without their replica", code)
	}
	if _, _, code = open(replicaSection(address, filepath.Join(dir, "primary.crt"), filepath.Join(dir, "primary.key"), filepath.Join(dir, "primary.crt"), "")); code != "authority_replica_configuration_invalid" {
		t.Fatal("the primary's certificate pinned as the replica's", code)
	}
	k, a, code = open(section)
	if code != "" {
		t.Fatal(code)
	}
	// The worker's writes, through the service, reach the replica.
	worker, stop := serveWorker(t, k, a)
	agent, volume := "agt_"+strings.Repeat("a", 32), "vol_"+strings.Repeat("b", 32)
	if err = worker.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	if _, err = worker.Register(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	position, err := replica.Position(ctx)
	if err != nil || position.Seq != 2 {
		t.Fatal("the worker's writes did not reach the replica", position, err)
	}
	stop()
	a.Close()
	// Half-armed authorities are refused.
	if err = os.Remove(filepath.Join(keyRoot, "replicated")); err != nil {
		t.Fatal(err)
	}
	if _, _, code = open(section); code != "restore_authority_unavailable" {
		t.Fatal("half-armed authorities opened", code)
	}
	if err = os.WriteFile(filepath.Join(keyRoot, "replicated"), []byte("replicated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The section needs absolute paths and an address with its port.
	for name, bad := range map[string]string{
		"relative certificate": replicaSection(address, "primary.crt", filepath.Join(dir, "primary.key"), filepath.Join(dir, "replica.crt"), ""),
		"address without port": replicaSection("standby", filepath.Join(dir, "primary.crt"), filepath.Join(dir, "primary.key"), filepath.Join(dir, "replica.crt"), ""),
	} {
		if _, err = parseConfig([]byte(primaryText(keyRoot, keyID, restoreRoot, restoreID, bad))); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	// The delay before degraded mode: 30 seconds by default, from 5 seconds
	// to 10 minutes.
	for value, want := range map[string]time.Duration{"": 0, "5s": 5 * time.Second, "45s": 45 * time.Second, "10m": 10 * time.Minute,
		"4s": -1, "11m": -1, "0s": -1, "-30s": -1, "thirty": -1} {
		text := primaryText(keyRoot, keyID, restoreRoot, restoreID,
			replicaSection(address, filepath.Join(dir, "primary.crt"), filepath.Join(dir, "primary.key"), filepath.Join(dir, "replica.crt"), value))
		if value == "" {
			text = primaryText(keyRoot, keyID, restoreRoot, restoreID, section)
		}
		c, err := parseConfig([]byte(text))
		if want < 0 && err == nil || want >= 0 && (err != nil || c.link.DegradedAfter != want) {
			t.Fatal("degraded_after", value, err)
		}
	}
	if _, _, code = open(replicaSection(address, filepath.Join(dir, "primary.crt"), filepath.Join(dir, "primary.key"), filepath.Join(dir, "replica.crt"), "45s")); code != "" {
		t.Fatal("a delay was refused", code)
	}
}

// After a failover, the service on the standby opens the promoted
// authorities with their pinned identities, and the worker runs on them
// through it. Without authority_replica they run alone and every write
// proceeds; the section is refused until a snapshot arms them for a new
// standby, which every write then reaches, under the new epoch.
func TestWorkerRunsOnPromotedAuthorities(t *testing.T) {
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
	defer catalog.Close()
	restoreID, keyID := catalog.Identity(), keys.Identity()
	unlockText, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := authoritylog.ParseUnlockKey(unlockText)
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
	defer replica.Close()
	if err = catalog.Replicate(ctx, replica); err != nil {
		t.Fatal(err)
	}
	keys.SetJournal(catalog)
	agent, volume := "agt_"+strings.Repeat("a", 32), "vol_"+strings.Repeat("b", 32)
	if err = keys.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	if _, err = catalog.Register(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	// The failover: the primary is gone; the standby's replica is promoted
	// into the directories its service uses.
	standby := filepath.Join(dir, "standby")
	keyRoot, restoreRoot := filepath.Join(standby, "keys"), filepath.Join(standby, "restore")
	promotion, err := restoreauthority.Promote(ctx, filepath.Join(dir, "replica"), restoreRoot, keyRoot, unlock)
	if err != nil || promotion.Epoch != 2 {
		t.Fatal(promotion, err)
	}
	open := func(extra string) (*keyauthority.Files, *restoreauthority.Catalog, string) {
		t.Helper()
		c, err := parseConfig([]byte(primaryText(keyRoot, keyID, restoreRoot, restoreID, extra)))
		if err != nil {
			t.Fatal(err)
		}
		k, a, code := openPrimary(ctx, c)
		if code == "" {
			t.Cleanup(func() { a.Close() })
		}
		return k, a, code
	}
	// No standby yet: every write proceeds, a new key, a seal and a
	// destruction too.
	k, a, code := open("")
	if code != "" {
		t.Fatal(code)
	}
	if state, err := a.Replication(ctx); err != nil || state.Armed || state.Committed.Epoch != 2 {
		t.Fatal("promoted authorities", state, err)
	}
	worker, stop := serveWorker(t, k, a)
	if status, err := worker.Status(ctx); err != nil || status.Epoch != 2 || status.Mode != restoreauthority.ModeStandalone {
		t.Fatal("the promoted authorities' service", status, err)
	}
	if err = worker.Ensure(ctx, agent, "vol_"+strings.Repeat("c", 32)); err != nil {
		t.Fatal(err)
	}
	gone := restoreauthority.Binding{Store: agent, Volume: volume, Incarnation: 1}
	if err = worker.RecordRetiredSeal(ctx, gone); err != nil {
		t.Fatal(err)
	}
	if err = worker.DestroyKey(ctx, gone); err != nil {
		t.Fatal(err)
	}
	stop()
	// authority_replica before a new standby is seeded: refused.
	writeLinkCertificates(t, standby, restoreID, keyID)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	section := replicaSection(listener.Addr().String(), filepath.Join(standby, "primary.crt"), filepath.Join(standby, "primary.key"), filepath.Join(standby, "replica.crt"), "")
	if _, _, code = open(section); code != "authority_replica_not_armed" {
		t.Fatal("replica configured for promoted authorities not yet armed", code)
	}
	// Seed a new standby from the promoted authorities, with a new unlock
	// key: the service is stopped.
	_, newRecipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Snapshot(ctx, k, newRecipient, filepath.Join(dir, "seed.sqlite")); err != nil {
		t.Fatal(err)
	}
	a.Close()
	seeded, err := restoreauthority.InitializeReplica(ctx, filepath.Join(dir, "new-replica"), filepath.Join(dir, "seed.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer seeded.Close()
	server, err := authoritylog.TLSFiles{Certificate: filepath.Join(standby, "replica.crt"), Key: filepath.Join(standby, "replica.key"),
		PeerCertificate: filepath.Join(standby, "primary.crt"), RestoreAuthority: restoreID, KeyAuthority: keyID}.ServerTLS()
	if err != nil {
		t.Fatal(err)
	}
	serving, cancel := context.WithCancel(ctx)
	defer cancel()
	go (&authoritylog.Server{Replica: seeded, Config: server}).Serve(serving, listener)
	k, a, code = open(section)
	if code != "" {
		t.Fatal(code)
	}
	worker, stop = serveWorker(t, k, a)
	defer stop()
	before, err := seeded.Position(ctx)
	if err != nil || before.Epoch != 2 {
		t.Fatal(before, err)
	}
	if err = worker.Ensure(ctx, agent, "vol_"+strings.Repeat("d", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = worker.Register(ctx, "store-new", "volume-new"); err != nil {
		t.Fatal(err)
	}
	if after, err := seeded.Position(ctx); err != nil || after.Epoch != 2 || after.Seq != before.Seq+2 {
		t.Fatal("the worker's writes did not reach the new standby", after, err)
	}
}
