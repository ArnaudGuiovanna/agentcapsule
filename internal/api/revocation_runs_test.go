//go:build linux && cgo

package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// These tests project two runs of spec/restore_authority_test.qnt (module
// restoreAuthorityReplicaTests) onto the real code: the authority service
// with its replica on a standby and degraded mode, and the API on
// PostgreSQL. The model's revokeAccess(1) revokes a standing grant (here a
// member); its acknowledged revocation is the API's confirmed one (ADR 006
// §7). degrade is the standby becoming unreachable and the delay passing;
// restoreLink then resync is the standby answering again and the replica
// catching up.

// standbyLink is the link to the replica, which the test cuts and restores.
type standbyLink struct {
	mu     sync.Mutex
	target authoritylog.Link
	down   bool
}

func (l *standbyLink) Sync(ctx context.Context, r authoritylog.Request) (authoritylog.Position, error) {
	l.mu.Lock()
	down, target := l.down, l.target
	l.mu.Unlock()
	if down {
		return authoritylog.Position{}, errors.New("standby unreachable")
	}
	return target.Sync(ctx, r)
}

func (l *standbyLink) set(down bool) {
	l.mu.Lock()
	l.down = down
	l.mu.Unlock()
}

// replicatedAuthority is an authority service armed for a replica, served
// in this process, and its API client.
type replicatedAuthority struct {
	catalog *restoreauthority.Catalog
	replica *restoreauthority.Replica
	link    *standbyLink
	api     *authorityclient.API
	// The directory of both hosts' authorities and the unlock key, for a
	// failover (reconciliation_runs_test.go).
	dir    string
	keys   *keyauthority.Files
	unlock *authoritylog.UnlockKey
}

func newReplicatedAuthority(t *testing.T) *replicatedAuthority {
	t.Helper()
	ctx := t.Context()
	dir := t.TempDir()
	keys, err := keyauthority.Initialize(ctx, filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(ctx, filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	text, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := authoritylog.ParseUnlockKey(text)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err = catalog.Snapshot(ctx, keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := restoreauthority.InitializeReplica(ctx, filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { replica.Close() })
	a := &replicatedAuthority{catalog: catalog, replica: replica, link: &standbyLink{target: replica}, dir: dir, keys: keys, unlock: unlock}
	if err = svc.LinkTo(ctx, catalog, keys, a.link, authoritylog.MinDegradedAfter); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	server, err := svc.New(ctx, svc.Config{Catalog: catalog, Keys: keys, WorkerUID: uid, APIUID: uid, Started: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	sockets, err := os.MkdirTemp("", "acrun-") // a socket path has at most 107 bytes
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sockets, "api.sock")
	listener, err := svc.Listen(socket, 0660)
	if err != nil {
		t.Fatal(err)
	}
	serving, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(serving, nil, listener) }()
	if a.api, err = authorityclient.NewAPI(socket, catalog.Identity(), keys.Identity()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.api.Close()
		stop()
		<-done
		os.RemoveAll(sockets)
	})
	a.waitMode(t, restoreauthority.ModeSynchronous)
	return a
}

func (a *replicatedAuthority) waitMode(t *testing.T, mode string) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		status, err := a.api.Status(t.Context())
		if err == nil && status.Mode == mode {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the authority service is not", mode, status, err)
		}
	}
}

// degrade: the standby stops answering. A delivery's outcome finds it
// unreachable, as every write does within the delay; then the delay
// passes. The outcome, a kind that continues in degraded mode, then holds
// back nothing.
func (a *replicatedAuthority) degrade(t *testing.T) {
	t.Helper()
	store, err := a.catalog.Register(t.Context(), "probe", "probe-volume")
	if err != nil {
		t.Fatal(err)
	}
	a.link.set(true)
	probe, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	outcome := restoreauthority.Outcome{ID: "probe-outcome", Digest: [32]byte{1}}
	if err = a.catalog.RecordOutcome(probe, store, outcome); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("a write returned without the replica, before degraded mode", err)
	}
	a.waitMode(t, restoreauthority.ModeDegraded)
}

// resync: the standby answers again, and the replica catches up; degraded
// mode ends once it holds the last degraded write.
func (a *replicatedAuthority) resync(t *testing.T) {
	t.Helper()
	a.link.set(false)
	a.waitMode(t, restoreauthority.ModeSynchronous)
}

func (a *replicatedAuthority) held(t *testing.T) map[string]bool {
	t.Helper()
	records, err := a.replica.AccessRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]bool{}
	for _, r := range records {
		held[r.ID] = true
	}
	return held
}

// revokeMember revokes a member through the API and returns its revocation.
func revokeMember(t *testing.T, l *apiDelegationFixture, owner, principal string) controlplane.AccessRevocation {
	t.Helper()
	r := call(t, l.server, "POST", "/v1/members/"+principal+"/revoke", owner, "revoke-"+principal, `{}`)
	revocations := revocationsOf(t, r.Body.Bytes())
	if r.Code != 200 || len(revocations) != 1 || revocations[0].Kind != "member" {
		t.Fatal("the member's revocation", r.Code, r.Body.String())
	}
	return revocations[0]
}

// grantRevocationWaitsForReplicaTest:
// init.then(degrade).then(revokeAccess(1).fail()). In degraded mode the
// API never confirms a standing grant's revocation: it takes effect at once
// on the primary, its record stays off the replica, and the API reports it
// pending, in its answer, its resource and on every later question. A
// bearer token's is confirmed at once: the blanket revocation at a failover
// covers it.
func TestGrantRevocationWaitsForReplica(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	a := newReplicatedAuthority(t)
	l.store.RecordAccessWith(a.api)
	member := apiAddMember(t, l, owner, "grant-leaver", "agent_user")
	token := l.sign(t, at, "grant-leaver-token", "grant-leaver", allAgentScopes)
	var account controlplane.ServiceAccount
	if r := call(t, l.server, "POST", "/v1/service-accounts", owner, "grant-bot", `{"name":"bot","role":"agent_user"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &account) != nil {
		t.Fatal(r.Code, r.Body.String())
	}
	var issued controlplane.IssuedServiceToken
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if r := call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens", owner, "grant-bot-token", `{"scopes":["org:read"],"expires_at":"`+expires+`"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &issued) != nil {
		t.Fatal(r.Code, r.Body.String())
	}

	a.degrade(t)
	grant := revokeMember(t, l, owner, member.PrincipalID)
	if grant.State != controlplane.RevocationPending || grant.ConfirmedAt != nil {
		t.Fatal("a standing grant's revocation confirmed in degraded mode", grant)
	}
	if call(t, l.server, "GET", "/v1/organizations/current", token, "", "").Code != 401 {
		t.Fatal("the revocation did not take effect at once on the primary")
	}
	records, err := a.catalog.AccessRecords(t.Context())
	if err != nil || len(records) != 1 || records[0].ID != grant.ID || records[0].Kind != "member" || records[0].Organization != l.org.ID {
		t.Fatal("the primary's record", records, err)
	}
	if a.held(t)[grant.ID] {
		t.Fatal("the replica holds the record in degraded mode")
	}
	for range 3 {
		if n, err := l.store.ConfirmAccessRevocations(t.Context(), 100); err != nil || n != 0 {
			t.Fatal("confirmed while the replica lacks it", n, err)
		}
	}
	r := call(t, l.server, "GET", "/v1/access-revocations/"+grant.ID, owner, "", "")
	var v controlplane.AccessRevocation
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v.State != controlplane.RevocationPending {
		t.Fatal("the revocation's resource", r.Code, r.Body.String())
	}
	r = call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens/"+issued.ID+"/revoke", owner, "grant-revoke-token", `{}`)
	bearer := revocationsOf(t, r.Body.Bytes())
	if r.Code != 200 || len(bearer) != 1 || bearer[0].Kind != "service_token" || bearer[0].State != controlplane.RevocationConfirmed {
		t.Fatal("a bearer token's revocation in degraded mode", r.Code, r.Body.String())
	}
	if a.held(t)[bearer[0].ID] {
		t.Fatal("the replica holds the token's record in degraded mode")
	}
}

// grantRevocationResumesAfterResyncTest:
// init.then(degrade).then(restoreLink).then(resync).then(revokeAccess(1)).
// Once the replica has caught up, a standing grant's revocation is
// confirmed at once, and the replica holds its record. The revocation left
// pending in degraded mode is confirmed too, once the replica holds it.
func TestGrantRevocationResumesAfterResync(t *testing.T) {
	l, _, owner := apiAgentsLab(t)
	a := newReplicatedAuthority(t)
	l.store.RecordAccessWith(a.api)
	first := apiAddMember(t, l, owner, "resync-first", "agent_user")
	second := apiAddMember(t, l, owner, "resync-second", "agent_user")
	a.degrade(t)
	pending := revokeMember(t, l, owner, first.PrincipalID)
	if pending.State != controlplane.RevocationPending {
		t.Fatal("confirmed in degraded mode", pending)
	}
	a.resync(t)
	if !a.held(t)[pending.ID] {
		t.Fatal("the resync did not bring the degraded record to the replica")
	}
	if n, err := l.store.ConfirmAccessRevocations(t.Context(), 100); err != nil || n != 1 {
		t.Fatal("the pending revocation was not confirmed after the resync", n, err)
	}
	r := call(t, l.server, "GET", "/v1/access-revocations/"+pending.ID, owner, "", "")
	var v controlplane.AccessRevocation
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v.State != controlplane.RevocationConfirmed || v.ConfirmedAt == nil {
		t.Fatal("the revocation's resource after the resync", r.Code, r.Body.String())
	}
	now := revokeMember(t, l, owner, second.PrincipalID)
	if now.State != controlplane.RevocationConfirmed || now.ConfirmedAt == nil {
		t.Fatal("a standing grant's revocation after the resync", now)
	}
	if !a.held(t)[now.ID] {
		t.Fatal("the replica lacks a confirmed revocation's record")
	}
}
