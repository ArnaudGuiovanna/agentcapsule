//go:build linux

// agentcapsule-authority holds the replica of the key and restore
// authorities on the standby host (docs/adr/005-keys-outside-restored-domain.md,
// option a), and prepares it:
//
//	unlock-key     generate the operator's unlock key (kept off both hosts)
//	certificate    generate one side's certificate for the mutual-TLS link
//	snapshot       on the primary: arm both authorities, write the replica's start
//	init-replica   on the standby: create the replica from a snapshot
//	serve          on the standby: receive the primary's records
//	promote        on the standby, once the old primary is stopped: turn the
//	               replica into both authorities, under the next epoch
//
// It is a separate binary, not a worker mode: the standby runs no worker,
// no VM and no database writer, and the replica runs as an unprivileged
// account that owns only its directory. Output is JSON; no secret is ever
// written to standard output.
package main

import (
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
	keyRoot := f.String("key-authority-root", "", "the worker's key_authority.root")
	keyID := f.String("key-authority-id", "", "the worker's key_authority.identity")
	restoreRoot := f.String("restore-authority-root", "", "the worker's restore_authority.root")
	restoreID := f.String("restore-authority-id", "", "the worker's restore_authority.identity")
	recipientText := f.String("recipient", "", "the unlock key's recipient, from unlock-key")
	out := f.String("out", "", "new snapshot file, outside both authorities")
	if !parse(f, args) || *keyRoot == "" || *restoreRoot == "" || *out == "" {
		return fail("configuration_required")
	}
	recipient, err := authoritylog.ParseRecipient(*recipientText)
	if err != nil {
		return fail("recipient_invalid")
	}
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

// serveConfig is the replica's configuration file.
type serveConfig struct {
	Version            int    `json:"version"`
	Root               string `json:"root"`
	RestoreAuthority   string `json:"restore_authority_id"`
	KeyAuthority       string `json:"key_authority_id"`
	Listen             string `json:"listen"`
	Certificate        string `json:"certificate"`
	Key                string `json:"key"`
	PrimaryCertificate string `json:"primary_certificate"`
	MetricsListen      string `json:"metrics_listen,omitempty"`
}

func loadConfig(path string) (serveConfig, error) {
	var c serveConfig
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return c, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return c, err
	}
	owner := st.Sys().(*syscall.Stat_t).Uid
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || (owner != 0 && owner != uint32(os.Geteuid())) || st.Size() > 65536 {
		return c, errors.New("configuration must be a bounded regular file, owned by root or this account, not writable by others")
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if d.More() || c.Version != 1 || !filepath.IsAbs(c.Root) {
		return c, errors.New("invalid configuration")
	}
	return c, nil
}

func serve(args []string) int {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := f.String("config", "", "replica JSON configuration")
	if !parse(f, args) || *path == "" {
		return fail("configuration_required")
	}
	c, err := loadConfig(*path)
	if err != nil {
		return fail("configuration_invalid")
	}
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
	if c.MetricsListen != "" {
		host, _, err := net.SplitHostPort(c.MetricsListen)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			return fail("metrics_listen_must_be_loopback")
		}
		listener, err := net.Listen("tcp", c.MetricsListen)
		if err != nil {
			return fail("metrics_listener_unavailable")
		}
		server := &http.Server{Handler: registry.Handler(5 * time.Second), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second,
			ErrorLog: log.New(io.Discard, "", 0)}
		go func() { _ = server.Serve(listener) }()
		defer server.Close()
	}
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
// runs as the worker's account, which must own the replica's directory: the
// keys it writes in clear belong to the worker, never to the replica's
// account. The old primary must be stopped first (docs/recovery.md).
func promote(args []string) int {
	f := flag.NewFlagSet("promote", flag.ContinueOnError)
	replicaRoot := f.String("replica-root", "", "the replica's directory, owned by this account")
	keyRoot := f.String("key-authority-root", "", "new directory: the worker's key_authority.root on this host")
	keyID := f.String("key-authority-id", "", "the key authority's identity, as the worker pins it")
	restoreRoot := f.String("restore-authority-root", "", "new directory: the worker's restore_authority.root on this host")
	restoreID := f.String("restore-authority-id", "", "the restore authority's identity, as the worker pins it")
	unlockPath := f.String("unlock-key-file", "", "private file holding the unlock key, from the safe")
	if !parse(f, args) || *replicaRoot == "" || *keyRoot == "" || *keyID == "" || *restoreRoot == "" || *restoreID == "" ||
		!filepath.IsAbs(*unlockPath) {
		return fail("configuration_required")
	}
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
	result, err := restoreauthority.Promote(ctx, *replicaRoot, *restoreRoot, *keyRoot, unlock)
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
		RestoreAuthority string `json:"restore_authority_id"`
		KeyAuthority     string `json:"key_authority_id"`
		Epoch            uint64 `json:"epoch"`
		PreviousEpoch    uint64 `json:"previous_epoch"`
		Sequence         uint64 `json:"sequence"`
	}{result.RestoreAuthority, result.KeyAuthority, result.Epoch, result.Position.Epoch, result.Position.Seq})
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
