//go:build linux && cgo

package worker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The authority_replica section: standalone without it, refused when it
// disagrees with the authorities, and synchronous with it.
func TestAuthorityReplicaConfiguration(t *testing.T) {
	dir := t.TempDir()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(t.Context(), filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	catalog.Close()
	c := ServiceConfig{Root: filepath.Join(dir, "runtime"),
		KeyAuthority:     &ServiceKeyAuthority{Root: filepath.Join(dir, "keys"), Identity: keys.Identity()},
		RestoreAuthority: &ServiceKeyAuthority{Root: filepath.Join(dir, "restore"), Identity: catalog.Identity()}}
	open := func() (*keyauthority.Files, *restoreauthority.Catalog, error) {
		k, err := c.OpenVolumeKeys()
		if err != nil {
			t.Fatal(err)
		}
		a, err := c.OpenRestoreAuthority(t.Context(), k)
		if err == nil {
			t.Cleanup(func() { a.Close() })
		}
		return k, a, err
	}
	// Standalone: the explicit default, without disaster protection.
	_, a, err := open()
	if err != nil {
		t.Fatal(err)
	}
	registry := telemetry.NewRegistry()
	a.ObserveReplication(authoritylog.NewMetrics(registry))
	var out strings.Builder
	registry.WriteTo(&out)
	if !strings.Contains(out.String(), "agentcapsule_authority_replication_enabled 0\n") {
		t.Fatal("standalone mode not reported")
	}
	for _, role := range []string{"primary", "replica"} {
		certificate, key, err := authoritylog.GenerateCertificate(role, catalog.Identity(), keys.Identity())
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.AuthorityReplica = &ServiceAuthorityReplica{Address: listener.Addr().String(), Certificate: filepath.Join(dir, "primary.crt"),
		Key: filepath.Join(dir, "primary.key"), ReplicaCertificate: filepath.Join(dir, "replica.crt")}
	if _, _, err = open(); AuthorityFailure(err) != "authority_replica_not_armed" {
		t.Fatal("replica configured for authorities never armed", err)
	}
	// Arm both authorities and build the replica.
	keys, err = c.OpenVolumeKeys()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	_, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Snapshot(t.Context(), keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := restoreauthority.InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	server, err := authoritylog.TLSFiles{Certificate: filepath.Join(dir, "replica.crt"), Key: filepath.Join(dir, "replica.key"),
		PeerCertificate: filepath.Join(dir, "primary.crt"), RestoreAuthority: catalog.Identity(), KeyAuthority: keys.Identity()}.ServerTLS()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go (&authoritylog.Server{Replica: replica, Config: server}).Serve(ctx, listener)
	section := c.AuthorityReplica
	c.AuthorityReplica = nil
	if _, _, err = open(); AuthorityFailure(err) != "authority_replica_required" {
		t.Fatal("armed authorities opened without their replica", err)
	}
	c.AuthorityReplica = &ServiceAuthorityReplica{Address: section.Address, Certificate: section.Certificate, Key: section.Key, ReplicaCertificate: section.Certificate}
	if _, _, err = open(); AuthorityFailure(err) != "authority_replica_configuration_invalid" {
		t.Fatal("the primary's certificate pinned as the replica's", err)
	}
	c.AuthorityReplica = section
	k, a, err := open()
	if err != nil {
		t.Fatal(err)
	}
	agent, volume := "agt_"+strings.Repeat("a", 32), "vol_"+strings.Repeat("b", 32)
	if err = k.Ensure(t.Context(), agent, volume); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Register(t.Context(), agent, volume); err != nil {
		t.Fatal(err)
	}
	position, err := replica.Position(t.Context())
	if err != nil || position.Seq != 2 {
		t.Fatal("the worker's writes did not reach the replica", position, err)
	}
	// Half-armed authorities are refused.
	if err = os.Remove(filepath.Join(dir, "keys", "replicated")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = open(); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("half-armed authorities opened", err)
	}
	// Settings: the section needs both authorities and absolute paths.
	s := ServiceConfig{Version: 1, HostID: "host", BootTimeout: "30s", BootLease: "2m", PollInterval: "1s", AttemptTimeout: "45s", AuthorityReplica: section}
	if _, _, _, err = s.Settings(); err == nil {
		t.Fatal("replica without authorities")
	}
	s.KeyAuthority, s.RestoreAuthority = c.KeyAuthority, c.RestoreAuthority
	if _, _, _, err = s.Settings(); err != nil {
		t.Fatal(err)
	}
	s.AuthorityReplica = &ServiceAuthorityReplica{Address: section.Address, Certificate: "primary.crt", Key: section.Key, ReplicaCertificate: section.ReplicaCertificate}
	if _, _, _, err = s.Settings(); err == nil {
		t.Fatal("relative certificate path accepted")
	}
	s.AuthorityReplica = &ServiceAuthorityReplica{Address: "standby", Certificate: section.Certificate, Key: section.Key, ReplicaCertificate: section.ReplicaCertificate}
	if _, _, _, err = s.Settings(); err == nil {
		t.Fatal("address without a port accepted")
	}
}
