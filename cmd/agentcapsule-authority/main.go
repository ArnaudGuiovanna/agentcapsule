//go:build linux

// agentcapsule-authority owns the key and restore authorities: on the
// primary host, the authority service that the worker reaches through its
// socket (docs/adr/006-authority-service.md); on the standby, their replica
// (docs/adr/005-keys-outside-restored-domain.md, option a). It also prepares
// the replica:
//
//	unlock-key     generate the operator's unlock key (kept off both hosts)
//	certificate    generate one side's certificate for the mutual-TLS link
//	snapshot       on the primary, the service stopped: arm both
//	               authorities, write the replica's start
//	init-replica   on the standby: create the replica from a snapshot
//	serve          on the primary, with "role": "primary", the authority
//	               service; on the standby, receive the primary's records
//	promote        on the standby, once the old primary is stopped: turn the
//	               replica into both authorities, under the next epoch
//
// It is a separate binary, not a worker mode: it runs as the unprivileged
// account agentcapsule-authority, which owns the directories, on both hosts.
// The standby runs no worker, no VM and no database writer. Output is JSON;
// no secret is ever written to standard output.
//
// One process at a time opens an authority directory: serve holds the lock
// of its directories while it runs, and snapshot, init-replica and promote
// refuse with authority_in_use while another process holds one.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

const usage = "usage: agentcapsule-authority unlock-key | certificate | snapshot | init-replica | serve | promote"

func fail(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }

func output(v any) int {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		return fail("output_failed")
	}
	return 0
}

// create writes a new file; it never replaces one.
func create(path string, data []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute path required")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

func parse(f *flag.FlagSet, args []string) bool {
	return f.Parse(args) == nil && f.NArg() == 0
}

// own takes the lock of the authority directories a command opens, or
// returns the code of its failure: authority_in_use while the service, or
// another command, holds one.
func own(dirs ...string) (*authorityservice.Owner, string) {
	owner, err := authorityservice.Own(dirs...)
	switch {
	case errors.Is(err, authorityservice.ErrInUse):
		return nil, "authority_in_use"
	case err != nil:
		return nil, "authority_directory_unavailable"
	}
	return owner, ""
}

func unlockKey(args []string) int {
	f := flag.NewFlagSet("unlock-key", flag.ContinueOnError)
	out := f.String("out", "", "new private file for the unlock key; move it off both hosts")
	if !parse(f, args) || *out == "" {
		return fail("configuration_required")
	}
	text, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		return fail("unlock_key_generation_failed")
	}
	defer clear(text)
	if err = create(*out, text, 0600); err != nil {
		return fail("unlock_key_file_not_written")
	}
	return output(struct {
		Recipient string `json:"recipient"`
	}{recipient.String()})
}

func certificate(args []string) int {
	f := flag.NewFlagSet("certificate", flag.ContinueOnError)
	role := f.String("role", "", "primary or replica")
	restore := f.String("restore-authority-id", "", "pinned restore authority identity")
	keys := f.String("key-authority-id", "", "pinned key authority identity")
	certificatePath := f.String("certificate", "", "new certificate file (public)")
	keyPath := f.String("key", "", "new private key file")
	if !parse(f, args) || *certificatePath == "" || *keyPath == "" || *certificatePath == *keyPath {
		return fail("configuration_required")
	}
	cert, key, err := authoritylog.GenerateCertificate(*role, *restore, *keys)
	if err != nil {
		return fail("certificate_configuration_invalid")
	}
	defer clear(key)
	if err = create(*keyPath, key, 0600); err != nil {
		return fail("key_file_not_written")
	}
	if err = create(*certificatePath, cert, 0644); err != nil {
		os.Remove(*keyPath)
		return fail("certificate_file_not_written")
	}
	fingerprint, _ := authoritylog.Fingerprint(cert)
	return output(struct {
		Role   string `json:"role"`
		SHA256 string `json:"sha256"`
	}{*role, fingerprint})
}

func snapshot(args []string) int {
	f := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	keyRoot := f.String("key-authority-root", "", "the service's key_authority.root")
	keyID := f.String("key-authority-id", "", "the service's key_authority.identity")
	restoreRoot := f.String("restore-authority-root", "", "the service's restore_authority.root")
	restoreID := f.String("restore-authority-id", "", "the service's restore_authority.identity")
	recipientText := f.String("recipient", "", "the unlock key's recipient, from unlock-key")
	out := f.String("out", "", "new snapshot file, outside both authorities")
	if !parse(f, args) || *keyRoot == "" || *restoreRoot == "" || *out == "" {
		return fail("configuration_required")
	}
	recipient, err := authoritylog.ParseRecipient(*recipientText)
	if err != nil {
		return fail("recipient_invalid")
	}
	owner, code := own(*keyRoot, *restoreRoot)
	if code != "" {
		return fail(code)
	}
	defer owner.Release()
	keys, err := keyauthority.Open(*keyRoot, *keyID)
	if err != nil {
		return fail("key_authority_unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	catalog, err := restoreauthority.Open(ctx, *restoreRoot, *restoreID, keys.Identity())
	if err != nil {
		return fail("restore_authority_unavailable")
	}
	defer catalog.Close()
	position, err := catalog.Snapshot(ctx, keys, recipient, *out)
	switch {
	case errors.Is(err, restoreauthority.ErrConflict):
		return fail("snapshot_armed_with_another_unlock_key")
	case err != nil:
		return fail("snapshot_failed")
	}
	return output(struct {
		RestoreAuthority string `json:"restore_authority_id"`
		KeyAuthority     string `json:"key_authority_id"`
		Epoch            uint64 `json:"epoch"`
		Sequence         uint64 `json:"sequence"`
	}{catalog.Identity(), keys.Identity(), position.Epoch, position.Seq})
}

func initReplica(args []string) int {
	f := flag.NewFlagSet("init-replica", flag.ContinueOnError)
	root := f.String("root", "", "new private replica directory")
	snapshotPath := f.String("snapshot", "", "snapshot file from the primary")
	if !parse(f, args) || *root == "" || *snapshotPath == "" {
		return fail("configuration_required")
	}
	owner, code := own(*root)
	if code != "" {
		return fail(code)
	}
	defer owner.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	replica, err := restoreauthority.InitializeReplica(ctx, *root, *snapshotPath)
	switch {
	case errors.Is(err, restoreauthority.ErrConflict):
		return fail("replica_exists")
	case errors.Is(err, restoreauthority.ErrInput):
		return fail("snapshot_invalid")
	case err != nil:
		return fail("replica_initialization_failed")
	}
	defer replica.Close()
	position, err := replica.Position(ctx)
	if err != nil {
		return fail("replica_unavailable")
	}
	return output(struct {
		Epoch    uint64 `json:"epoch"`
		Sequence uint64 `json:"sequence"`
	}{position.Epoch, position.Seq})
}

// serveConfig is the replica's configuration file: version 1, or version 2
// with "role": "replica".
type serveConfig struct {
	Version            int    `json:"version"`
	Role               string `json:"role,omitempty"`
	Root               string `json:"root"`
	RestoreAuthority   string `json:"restore_authority_id"`
	KeyAuthority       string `json:"key_authority_id"`
	Listen             string `json:"listen"`
	Certificate        string `json:"certificate"`
	Key                string `json:"key"`
	PrimaryCertificate string `json:"primary_certificate"`
	MetricsListen      string `json:"metrics_listen,omitempty"`
}

// primaryConfig is the authority service's configuration on the primary:
// version 2 with "role": "primary" (docs/adr/006-authority-service.md §6).
type primaryConfig struct {
	Version          int                 `json:"version"`
	Role             string              `json:"role"`
	KeyAuthority     *authorityDirectory `json:"key_authority"`
	RestoreAuthority *authorityDirectory `json:"restore_authority"`
	WorkerSocket     string              `json:"worker_socket"`
	APISocket        string              `json:"api_socket"`
	APIUID           *uint32             `json:"api_uid"`
	// MaxKeyHold caps a hold of a key in use: 2m when empty, from 30s to 10m.
	MaxKeyHold string `json:"max_key_hold,omitempty"`
	// AuthorityReplica is the section the worker had before the service,
	// unchanged; the authorities are standalone without it.
	AuthorityReplica *replicaLink `json:"authority_replica,omitempty"`
	MetricsListen    string       `json:"metrics_listen,omitempty"`
}

type authorityDirectory struct {
	Root     string `json:"root"`
	Identity string `json:"identity"`
}

type replicaLink struct {
	Address            string `json:"address"`
	Certificate        string `json:"certificate"`
	Key                string `json:"key"`
	ReplicaCertificate string `json:"replica_certificate"`
	DegradedAfter      string `json:"degraded_after,omitempty"`
}

// config is a parsed configuration: one of the two roles.
type config struct {
	replica *serveConfig
	primary *primaryConfig
	// The primary's parsed values.
	maxKeyHold time.Duration
	link       *authorityservice.Replica
}

func readConfig(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	owner := st.Sys().(*syscall.Stat_t).Uid
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || (owner != 0 && owner != uint32(os.Geteuid())) || st.Size() > 65536 {
		return nil, errors.New("configuration must be a bounded regular file, owned by root or this account, not writable by others")
	}
	return io.ReadAll(io.LimitReader(f, 65537))
}

func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing configuration data")
	}
	return nil
}

func cleanPath(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

// parseConfig reads either role. A version 1 file is the replica's, as
// before the authority service; version 2 names its role.
func parseConfig(b []byte) (config, error) {
	var c config
	invalid := errors.New("invalid configuration")
	var head struct {
		Version int    `json:"version"`
		Role    string `json:"role"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return c, err
	}
	switch {
	case head.Version == 1 && head.Role == "", head.Version == 2 && head.Role == authoritylog.RoleReplica:
		r := &serveConfig{}
		if err := strict(b, r); err != nil {
			return c, err
		}
		if !filepath.IsAbs(r.Root) {
			return c, invalid
		}
		c.replica = r
		return c, nil
	case head.Version != 2 || head.Role != authoritylog.RolePrimary:
		return c, invalid
	}
	p := &primaryConfig{}
	if err := strict(b, p); err != nil {
		return c, err
	}
	if p.KeyAuthority == nil || p.RestoreAuthority == nil || p.APIUID == nil || *p.APIUID == 0 ||
		!cleanPath(p.KeyAuthority.Root) || !cleanPath(p.RestoreAuthority.Root) ||
		!authoritylog.ValidID(p.KeyAuthority.Identity, "keyauth_") || !authoritylog.ValidID(p.RestoreAuthority.Identity, "restoreauth_") ||
		restoreauthority.CheckSeparation(p.KeyAuthority.Root, p.RestoreAuthority.Root) != nil ||
		!cleanPath(p.WorkerSocket) || !cleanPath(p.APISocket) || p.WorkerSocket == p.APISocket ||
		len(p.WorkerSocket) > 100 || len(p.APISocket) > 100 {
		return c, invalid
	}
	c.maxKeyHold = authorityservice.DefaultMaxKeyHold
	if p.MaxKeyHold != "" {
		d, err := time.ParseDuration(p.MaxKeyHold)
		if err != nil || d < authorityservice.MinMaxKeyHold || d > authorityservice.MaxMaxKeyHold {
			return c, invalid
		}
		c.maxKeyHold = d
	}
	if r := p.AuthorityReplica; r != nil {
		if _, port, err := net.SplitHostPort(r.Address); err != nil || port == "" ||
			!cleanPath(r.Certificate) || !cleanPath(r.Key) || !cleanPath(r.ReplicaCertificate) {
			return c, invalid
		}
		c.link = &authorityservice.Replica{Address: r.Address, Certificate: r.Certificate, Key: r.Key, ReplicaCertificate: r.ReplicaCertificate}
		if r.DegradedAfter != "" {
			d, err := time.ParseDuration(r.DegradedAfter)
			if err != nil || d < authoritylog.MinDegradedAfter || d > authoritylog.MaxDegradedAfter {
				return c, invalid
			}
			c.link.DegradedAfter = d
		}
	}
	c.primary = p
	return c, nil
}

// serveMetrics serves the registry on a loopback address; it returns the
// failure's code, if any.
func serveMetrics(address string, registry *telemetry.Registry) (func(), string) {
	if address == "" {
		return func() {}, ""
	}
	host, _, err := net.SplitHostPort(address)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return nil, "metrics_listen_must_be_loopback"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, "metrics_listener_unavailable"
	}
	server := &http.Server{Handler: registry.Handler(5 * time.Second), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = server.Serve(listener) }()
	return func() { server.Close() }, ""
}

func serve(args []string) int {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := f.String("config", "", "JSON configuration of the replica, or of the primary's authority service")
	if !parse(f, args) || *path == "" {
		return fail("configuration_required")
	}
	b, err := readConfig(*path)
	if err != nil {
		return fail("configuration_invalid")
	}
	c, err := parseConfig(b)
	if err != nil {
		return fail("configuration_invalid")
	}
	if c.primary != nil {
		return servePrimary(c)
	}
	return serveReplica(*c.replica)
}

func serveReplica(c serveConfig) int {
	owner, code := own(c.Root)
	if code != "" {
		return fail(code)
	}
	defer owner.Release()
	refusals := append(authoritylog.RefusalKinds(), authoritylog.ErrorKinds()...)
	vocabulary := map[string][]string{"event": {"replica_started", "replica_refused", "replica_request_failed", "replica_stopped", "replica_promoted"}, "kind": refusals}
	events, problems := telemetry.NewLogger(os.Stdout, vocabulary), telemetry.NewLogger(os.Stderr, vocabulary)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	replica, err := restoreauthority.OpenReplica(ctx, c.Root, c.RestoreAuthority, c.KeyAuthority)
	if errors.Is(err, restoreauthority.ErrPromoted) {
		return fail("replica_promoted") // this host now runs the primary
	}
	if err != nil {
		return fail("replica_unavailable")
	}
	defer replica.Close()
	// A promotion stops the listener: the promoted replica takes no record,
	// and its host now runs the primary.
	ctx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	var promoted atomic.Bool
	onPromotion := func() { promoted.Store(true); stopServing() }
	go watchPromotion(ctx, replica, promotionCheck, onPromotion)
	config, err := authoritylog.TLSFiles{Certificate: c.Certificate, Key: c.Key, PeerCertificate: c.PrimaryCertificate,
		RestoreAuthority: c.RestoreAuthority, KeyAuthority: c.KeyAuthority}.ServerTLS()
	if err != nil {
		return fail("tls_configuration_invalid")
	}
	position, err := replica.Position(ctx)
	if err != nil {
		return fail("replica_unavailable")
	}
	registry := telemetry.NewRegistry()
	metrics := authoritylog.NewReplicaMetrics(registry)
	metrics.Started(position)
	replica.Observe(metrics)
	closeMetrics, code := serveMetrics(c.MetricsListen, registry)
	if code != "" {
		return fail(code)
	}
	defer closeMetrics()
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return fail("listener_unavailable")
	}
	server := &authoritylog.Server{Replica: replica, Config: config, Observe: func(err error) {
		var refusal *authoritylog.Refusal
		if errors.As(err, &refusal) {
			problems.Event("replica_refused", telemetry.Code("kind", refusal.Kind))
			if refusal.Kind == authoritylog.RefusedPromoted {
				onPromotion()
			}
			return
		}
		problems.Event("replica_request_failed", telemetry.Code("kind", authoritylog.ErrorKind(err)))
	}}
	events.Event("replica_started", telemetry.Int("epoch", int64(position.Epoch)), telemetry.Int("sequence", int64(position.Seq)))
	err = server.Serve(ctx, listener)
	events.Event("replica_stopped")
	if promoted.Load() {
		events.Event("replica_promoted")
		return fail("replica_promoted")
	}
	if errors.Is(err, context.Canceled) {
		return 0
	}
	return fail("replica_server_stopped")
}

// servePrimary runs the authority service on the primary: it owns both
// authorities, links them to the standby when authority_replica is set,
// and serves the worker socket (root only) and the API socket (api_uid and
// root).
func servePrimary(c config) int {
	p := c.primary
	owner, code := own(p.KeyAuthority.Root, p.RestoreAuthority.Root)
	if code != "" {
		return fail(code)
	}
	defer owner.Release()
	vocabulary := authorityservice.Vocabulary()
	vocabulary["event"] = append(vocabulary["event"], "service_started", "service_stopped")
	vocabulary["mode"] = []string{restoreauthority.ModeStandalone, restoreauthority.ModeSynchronous, restoreauthority.ModeDegraded, restoreauthority.ModeWaiting}
	events, problems := telemetry.NewLogger(os.Stdout, vocabulary), telemetry.NewLogger(os.Stderr, vocabulary)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	keys, catalog, code := openPrimary(ctx, c)
	if code != "" {
		return fail(code)
	}
	defer catalog.Close()
	registry := telemetry.NewRegistry()
	catalog.ObserveReplication(authoritylog.NewMetrics(registry))
	server, err := authorityservice.New(ctx, authorityservice.Config{Catalog: catalog, Keys: keys, APIUID: *p.APIUID,
		MaxKeyHold: c.maxKeyHold, Metrics: authorityservice.NewMetrics(registry), Logger: problems})
	if err != nil {
		return fail("restore_authority_unavailable")
	}
	worker, err := authorityservice.Listen(p.WorkerSocket, 0600)
	if err != nil {
		return fail("worker_socket_unavailable")
	}
	api, err := authorityservice.Listen(p.APISocket, 0660)
	if err != nil {
		worker.Close()
		return fail("api_socket_unavailable")
	}
	closeMetrics, code := serveMetrics(p.MetricsListen, registry)
	if code != "" {
		worker.Close()
		api.Close()
		return fail(code)
	}
	defer closeMetrics()
	mode, _ := catalog.ReplicationMode()
	events.Event("service_started", telemetry.Int("epoch", int64(server.Status().Epoch)), telemetry.Code("mode", mode))
	err = server.Serve(ctx, worker, api)
	events.Event("service_stopped")
	if errors.Is(err, context.Canceled) {
		return 0
	}
	return fail("service_stopped")
}

// openPrimary opens both authorities of the primary role, and links them to
// the standby when authority_replica is set; it returns the code of its
// failure. Standalone without the section, unless a snapshot armed them:
// then it refuses (authority_replica_required). Authorities that no snapshot
// armed, such as promoted ones before a new standby is seeded, refuse the
// section (authority_replica_not_armed). The caller holds their owner lock.
func openPrimary(ctx context.Context, c config) (*keyauthority.Files, *restoreauthority.Catalog, string) {
	p := c.primary
	keys, err := keyauthority.Open(p.KeyAuthority.Root, p.KeyAuthority.Identity)
	if err != nil {
		return nil, nil, "key_authority_unavailable"
	}
	catalog, err := restoreauthority.Open(ctx, p.RestoreAuthority.Root, p.RestoreAuthority.Identity, keys.Identity())
	if err != nil {
		return nil, nil, "restore_authority_unavailable"
	}
	// A catalogue of an older schema would refuse the access revocation
	// records: agentcapsule-admin init-restore-authority upgrades it, with
	// the service stopped.
	if err = catalog.CheckSchema(ctx); err != nil {
		catalog.Close()
		if errors.Is(err, restoreauthority.ErrUpgradeRequired) {
			return nil, nil, "restore_authority_upgrade_required"
		}
		return nil, nil, "restore_authority_unavailable"
	}
	code := ""
	switch err = authorityservice.Link(ctx, catalog, keys, c.link); {
	case err == nil:
		return keys, catalog, ""
	case errors.Is(err, restoreauthority.ErrReplicaRequired):
		code = "authority_replica_required"
	case errors.Is(err, restoreauthority.ErrNotArmed):
		code = "authority_replica_not_armed"
	case errors.Is(err, authorityservice.ErrReplicaConfiguration):
		code = "authority_replica_configuration_invalid"
	default:
		code = "restore_authority_unavailable"
	}
	catalog.Close()
	return nil, nil, code
}

// promotionCheck is how often serve looks for a promotion made by another
// process while no record arrives.
const promotionCheck = 2 * time.Second

// watchPromotion calls promoted once the replica is promoted, then returns;
// it also returns when ctx ends.
func watchPromotion(ctx context.Context, replica *restoreauthority.Replica, every time.Duration, promoted func()) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if status, err := replica.Status(ctx); err == nil && status.Promoted {
			promoted()
			return
		}
	}
}

// promote turns the replica into the two authorities of the new primary. It
// runs as agentcapsule-authority, which owns the replica's directory, so the
// promoted directories belong to the authority service's account. The old
// primary must be stopped first (docs/recovery.md).
func promote(args []string) int {
	f := flag.NewFlagSet("promote", flag.ContinueOnError)
	replicaRoot := f.String("replica-root", "", "the replica's directory, owned by this account")
	keyRoot := f.String("key-authority-root", "", "new directory: the service's key_authority.root on this host")
	keyID := f.String("key-authority-id", "", "the key authority's identity, as the worker pins it")
	restoreRoot := f.String("restore-authority-root", "", "new directory: the service's restore_authority.root on this host")
	restoreID := f.String("restore-authority-id", "", "the restore authority's identity, as the worker pins it")
	unlockPath := f.String("unlock-key-file", "", "private file holding the unlock key, from the safe")
	degradedAfter := f.Duration("degraded-after", authoritylog.DefaultDegradedAfter,
		"the old primary's authority_replica.degraded_after: a last contact older than this before the failover assumes a degraded period ran")
	if !parse(f, args) || *replicaRoot == "" || *keyRoot == "" || *keyID == "" || *restoreRoot == "" || *restoreID == "" ||
		!filepath.IsAbs(*unlockPath) || *degradedAfter < authoritylog.MinDegradedAfter || *degradedAfter > authoritylog.MaxDegradedAfter {
		return fail("configuration_required")
	}
	// The replica's listener and any service on the target directories must
	// be stopped (docs/recovery.md).
	owner, code := own(*replicaRoot, *keyRoot, *restoreRoot)
	if code != "" {
		return fail(code)
	}
	defer owner.Release()
	text, err := operatorconfig.ReadPrivateUpTo(*unlockPath, 256)
	if err != nil {
		return fail("unlock_key_file_must_be_private")
	}
	unlock, err := authoritylog.ParseUnlockKey(text)
	clear(text)
	if err != nil {
		return fail("unlock_key_invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	status, err := restoreauthority.InspectReplica(ctx, *replicaRoot)
	if err != nil {
		return fail("replica_unavailable")
	}
	if status.RestoreAuthority != *restoreID || status.KeyAuthority != *keyID {
		return fail("replica_identity_mismatch")
	}
	result, err := restoreauthority.PromoteWith(ctx, *replicaRoot, *restoreRoot, *keyRoot, unlock,
		restoreauthority.PromoteOptions{DegradedAfter: *degradedAfter})
	switch {
	case errors.Is(err, authoritylog.ErrWrap):
		return fail("unlock_key_does_not_open_replica")
	case errors.Is(err, restoreauthority.ErrStillReplicating):
		return fail("old_primary_still_replicating")
	case errors.Is(err, restoreauthority.ErrConflict), errors.Is(err, keyauthority.ErrConflict):
		return fail("promoted_authority_conflict")
	case err != nil:
		return fail("promotion_failed")
	}
	return output(struct {
		RestoreAuthority string       `json:"restore_authority_id"`
		KeyAuthority     string       `json:"key_authority_id"`
		Epoch            uint64       `json:"epoch"`
		PreviousEpoch    uint64       `json:"previous_epoch"`
		Sequence         uint64       `json:"sequence"`
		Announcement     announcement `json:"announcement"`
	}{result.RestoreAuthority, result.KeyAuthority, result.Epoch, result.Position.Epoch, result.Position.Seq, announced(result.Announcement)})
}

// announcement is what the failover announces (ADR 005, item 14): whether
// a degraded period may have run, its window, and the blanket revocation of
// bearer tokens. A promotion by a release before ADR 006 wave 7, repeated,
// knows none of it.
type announcement struct {
	Failover    *time.Time `json:"failover,omitempty"`
	LastContact *time.Time `json:"last_contact,omitempty"`
	Degraded    bool       `json:"degraded"`
	Window      *struct {
		From time.Time `json:"from"`
		To   time.Time `json:"to"`
	} `json:"window,omitempty"`
	Blanket string `json:"blanket_revocation_id,omitempty"`
}

func announced(a restoreauthority.Announcement) announcement {
	var out announcement
	if !a.Failover.IsZero() {
		failover := a.Failover.UTC()
		out.Failover = &failover
	}
	if !a.LastContact.IsZero() {
		contact := a.LastContact.UTC()
		out.LastContact = &contact
	}
	out.Degraded, out.Blanket = a.Degraded, a.Blanket
	if a.Degraded {
		from := a.LastContact
		if from.After(a.Failover) {
			from = a.Failover
		}
		out.Window = &struct {
			From time.Time `json:"from"`
			To   time.Time `json:"to"`
		}{from.UTC(), a.Failover.UTC()}
	}
	return out
}

func run() int {
	if len(os.Args) < 2 {
		return fail(usage)
	}
	command, args := os.Args[1], os.Args[2:]
	switch command {
	case "unlock-key":
		return unlockKey(args)
	case "certificate":
		return certificate(args)
	case "snapshot":
		return snapshot(args)
	case "init-replica":
		return initReplica(args)
	case "serve":
		return serve(args)
	case "promote":
		return promote(args)
	}
	return fail(usage)
}

func main() { os.Exit(run()) }
