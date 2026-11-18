//go:build linux && cgo

package authorityservice

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// Replica is the link to the standby, the authority_replica section the
// service takes over from the worker's configuration: Certificate and Key
// are this host's side of the mutual TLS link, ReplicaCertificate pins the
// standby's. DegradedAfter is the delay before degraded mode; the default
// when zero.
type Replica struct {
	Address            string
	Certificate        string
	Key                string
	ReplicaCertificate string
	DegradedAfter      time.Duration
}

// ErrReplicaConfiguration marks unusable TLS files for the replica.
var ErrReplicaConfiguration = errors.New("invalid authority replica configuration")

// Link links both authorities to their replica, as the worker does today:
// the key authority journals through the catalogue, one stream for both.
// Without r they stay standalone, unless a snapshot armed them: then it
// refuses (restoreauthority.ErrReplicaRequired). Authorities that no
// snapshot armed refuse r (restoreauthority.ErrNotArmed). It returns
// without the replica: the catalogue's monitor reaches it in the
// background, and keeps trying while it does not answer.
func Link(ctx context.Context, catalog *restoreauthority.Catalog, keys *keyauthority.Files, r *Replica) error {
	state, err := catalog.Replication(ctx)
	if err != nil {
		return err
	}
	keysArmed, err := keys.Replicated()
	if err != nil {
		return err
	}
	if keysArmed != state.Armed {
		return restoreauthority.ErrUnavailable // armed by halves: take the snapshot again
	}
	if r == nil {
		if state.Armed {
			return restoreauthority.ErrReplicaRequired
		}
		return nil // standalone: no protection against the host's loss
	}
	if !state.Armed {
		return restoreauthority.ErrNotArmed
	}
	config, err := authoritylog.TLSFiles{Certificate: r.Certificate, Key: r.Key, PeerCertificate: r.ReplicaCertificate,
		RestoreAuthority: catalog.Identity(), KeyAuthority: keys.Identity()}.ClientTLS()
	if err != nil {
		return errors.Join(ErrReplicaConfiguration, err)
	}
	client, err := authoritylog.NewClient(r.Address, config)
	if err != nil {
		return errors.Join(ErrReplicaConfiguration, err)
	}
	if err = LinkTo(ctx, catalog, keys, client, r.DegradedAfter); err != nil {
		return err
	}
	// The heartbeat keeps the standby's last contact recent while nothing
	// is written: a promotion compares it with the degraded delay, and
	// announces the window from it (ADR 006 wave 7).
	after := r.DegradedAfter
	if after == 0 {
		after = authoritylog.DefaultDegradedAfter
	}
	catalog.KeepContact(restoreauthority.HeartbeatEvery(after))
	return nil
}

// LinkTo links both armed authorities to the replica behind link, and
// starts reaching it (ADR 006, wave 4): a service that no operation has
// used yet reports synchronous once the replica answers, not waiting. Tests
// run the stream in memory.
func LinkTo(ctx context.Context, catalog *restoreauthority.Catalog, keys *keyauthority.Files, link authoritylog.Link, degradedAfter time.Duration) error {
	if err := catalog.ReplicateWith(ctx, link, restoreauthority.ReplicationOptions{DegradedAfter: degradedAfter}); err != nil {
		return err
	}
	keys.SetJournal(catalog)
	catalog.ReachReplica()
	return nil
}
