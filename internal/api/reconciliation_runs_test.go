//go:build linux && cgo

package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests project the runs of the reconciliation and of the blanket
// revocation (spec/restore_authority_test.qnt, modules
// restoreAuthorityReplicaTests and restoreAuthorityDecidedDegradedTests;
// restoreWitnessEarlyOpenGuard in spec/restore_witness.qnt) onto the real
// code: the authority service with its replica, the promotion of that
// replica, a service on the promoted authorities, and PostgreSQL.
//
// The model's failover is losePrimary then promote: the standby promotes
// its replica, and PostgreSQL from its older copy. One database stands for
// both copies here: the writes the WAL did not ship are taken back by hand
// (setBack), which leaves PostgreSQL as its copy before them would be.
// shipWal is not taking them back. reconcileDatabase is
// agentcapsule-admin reconcile's Store.Reconcile, on the promoted service's
// API socket; openApi is the API's gate, at start and in its readiness probe
// (ReconciledAuthority).

// promotedService is the standby after a failover: its replica promoted,
// and the authority service in the primary role on the promoted
// authorities, standalone.
type promotedService struct {
	catalog   *restoreauthority.Catalog
	api       *authorityclient.API
	promotion restoreauthority.Promotion
}

// failover loses the primary: the standby stops hearing from it, and its
// replica is promoted at failover, which decides what the failover
// announces. The old primary's service stays in this process, unreachable:
// nothing uses it again.
func (a *replicatedAuthority) failover(t *testing.T, failover time.Time) *promotedService {
	t.Helper()
	ctx := t.Context()
	a.link.set(true)
	restoreRoot, keyRoot := filepath.Join(a.dir, "promoted-restore"), filepath.Join(a.dir, "promoted-keys")
	promotion, err := restoreauthority.PromoteWith(ctx, filepath.Join(a.dir, "replica"), restoreRoot, keyRoot, a.unlock,
		restoreauthority.PromoteOptions{Now: func() time.Time { return failover }})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyauthority.Open(keyRoot, promotion.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Open(ctx, restoreRoot, promotion.RestoreAuthority, promotion.KeyAuthority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })
	uid := uint32(os.Getuid())
	server, err := svc.New(ctx, svc.Config{Catalog: catalog, Keys: keys, WorkerUID: uid, APIUID: uid, Started: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	sockets, err := os.MkdirTemp("", "acrun-")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := svc.Listen(filepath.Join(sockets, "api.sock"), 0660)
	if err != nil {
		t.Fatal(err)
	}
	serving, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(serving, nil, listener) }()
	p := &promotedService{catalog: catalog, promotion: promotion}
	if p.api, err = authorityclient.NewAPI(filepath.Join(sockets, "api.sock"), catalog.Identity(), keys.Identity()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.api.Close()
		stop()
		<-done
		os.RemoveAll(sockets)
	})
	return p
}

// lastContact is the standby's last contact with the primary.
func (a *replicatedAuthority) lastContact(t *testing.T) time.Time {
	t.Helper()
	contact, err := a.replica.LastContact(t.Context())
	if err != nil || contact.IsZero() {
		t.Fatal("the standby's last contact", contact, err)
	}
	return contact
}

// execSQL runs statements on the lab's database beside the API.
func execSQL(t *testing.T, l *apiDelegationFixture, query string, args ...any) {
	t.Helper()
	db, err := pgxpool.New(t.Context(), l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(t.Context(), query, args...); err != nil {
		t.Fatal(query, err)
	}
}

func scalar[T any](t *testing.T, l *apiDelegationFixture, query string, args ...any) T {
	t.Helper()
	db, err := pgxpool.New(t.Context(), l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v T
	if err = db.QueryRow(t.Context(), query, args...).Scan(&v); err != nil {
		t.Fatal(query, err)
	}
	return v
}

// forget takes an access revocation's row back out of PostgreSQL, as a
// copy older than its commit lacks it.
func forget(t *testing.T, l *apiDelegationFixture, id string) {
	t.Helper()
	execSQL(t, l, `ALTER TABLE access_revocations DISABLE TRIGGER access_revocation_guard;
        DELETE FROM access_revocations WHERE id='`+id+`';
        ALTER TABLE access_revocations ENABLE TRIGGER access_revocation_guard`)
}

// setBackMember takes a member's revocation back: PostgreSQL as its copy
// before the revocation's commit.
func setBackMember(t *testing.T, l *apiDelegationFixture, principal string, revocation controlplane.AccessRevocation) {
	t.Helper()
	execSQL(t, l, `UPDATE memberships SET status='active' WHERE principal_id=$1`, principal)
	execSQL(t, l, `UPDATE team_memberships SET status='active' WHERE principal_id=$1`, principal)
	forget(t, l, revocation.ID)
}

// liveStore makes a tenant agent live in PostgreSQL, and registers its
// store in the authority with the volume PostgreSQL enrolled.
func liveStore(t *testing.T, l *apiDelegationFixture, a *replicatedAuthority, agent string) restoreauthority.Binding {
	t.Helper()
	execSQL(t, l, `UPDATE agents SET phase='LIVE' WHERE id=$1`, agent)
	volume := scalar[string](t, l, `SELECT volume_id FROM store_enrollments WHERE agent_id=$1`, agent)
	b, err := a.catalog.Register(t.Context(), agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// readiness wires the API's gate as agentcapsule-api does, on the promoted
// service, and returns the probe's status and problem code.
func readiness(t *testing.T, l *apiDelegationFixture, p *promotedService) (int, string) {
	t.Helper()
	l.server.ReportAuthority(ReconciledAuthority(l.store, func(ctx context.Context) (string, uint64, error) {
		status, err := p.api.Status(ctx)
		return status.Mode, status.Epoch, err
	}))
	r := call(t, l.server, "GET", "/v1/health/ready", "", "", "")
	var body map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err, r.Body.String())
	}
	code, _ := body["code"].(string)
	if r.Code == 200 {
		code, _ = body["authority"].(string)
	}
	return r.Code, code
}

// reconcile is the model's reconcileDatabase: agentcapsule-admin
// reconcile, on the promoted service's API socket.
func reconcile(t *testing.T, l *apiDelegationFixture, p *promotedService) controlplane.Reconciliation {
	t.Helper()
	r, err := l.store.Reconcile(t.Context(), p.api)
	if err != nil {
		t.Fatal("the reconciliation", err)
	}
	if r.Epoch != 2 || r.RestoreAuthority != p.catalog.Identity() {
		t.Fatal("the reconciliation's epoch", r)
	}
	return r
}

// reconciliationReplaysRootTest:
// init.then(revokeAccess(1)).then(beginRevocation(0)).then(permanentlySeal(0))
// .then(beginRestore(1)).then(failover).then(reconcileDatabase).then(openApi).
// The promoted database lacks a member's revocation, a revocation subject, a
// seal and a restore, all made after the last WAL shipment and held by the
// authority. The reconciliation replays the revocation, copies the subject,
// resumes the deletion of the sealed agent and reports the restored one; the
// API opens only then (noRevivedAccess, subjectsCopiedBack,
// deletionsResumed, divergenceReported).
func TestReconciliationReplaysRoot(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	a := newReplicatedAuthority(t)
	l.store.RecordAccessWith(a.api)
	ctx := t.Context()
	member := apiAddMember(t, l, owner, "replay-leaver", "agent_user")
	token := l.sign(t, at, "replay-leaver-token", "replay-leaver", allAgentScopes)
	sealed, restored := apiTenantAgent(t, l, owner, "sealed"), apiTenantAgent(t, l, owner, "restored")
	sealedStore, restoredStore := liveStore(t, l, a, sealed), liveStore(t, l, a, restored)

	grant := revokeMember(t, l, owner, member.PrincipalID)
	if grant.State != controlplane.RevocationConfirmed {
		t.Fatal("the member's revocation is not on the replica", grant)
	}
	// A request closed in the window: its subject, a role apart from the
	// stores'.
	subject := "request/req_" + strings.Repeat("5", 32)
	if _, err := a.catalog.BeginRevocation(ctx, subject); err != nil {
		t.Fatal(err)
	}
	if err := a.catalog.RecordRetiredSeal(ctx, sealedStore); err != nil {
		t.Fatal(err)
	}
	if _, err := a.catalog.ReserveIncarnation(ctx, restoredStore, "restore-in-the-window"); err != nil {
		t.Fatal(err)
	}
	// None of it reached the standby's PostgreSQL.
	setBackMember(t, l, member.PrincipalID, grant)
	p := a.failover(t, a.lastContact(t).Add(time.Second))
	if p.promotion.Announcement.Degraded {
		t.Fatal("a failover right after the last contact announced a degraded period", p.promotion.Announcement)
	}

	// openApi refused: the database revives the member until it is
	// reconciled.
	if err := l.store.CheckReconciled(ctx, 2); !errors.Is(err, controlplane.ErrNotReconciled) {
		t.Fatal("the API would open before the reconciliation", err)
	}
	if code, problem := readiness(t, l, p); code != 503 || problem != "authority_not_reconciled" {
		t.Fatal("the readiness before the reconciliation", code, problem)
	}

	r := reconcile(t, l, p)
	if r.Replayed != 1 || r.Kept != 0 || r.Announcement != nil {
		t.Fatal("what the reconciliation replayed", r)
	}
	if status := scalar[string](t, l, `SELECT status FROM memberships WHERE principal_id=$1`, member.PrincipalID); status != "revoked" {
		t.Fatal("the member's revocation was not replayed", status)
	}
	if code := call(t, l.server, "GET", "/v1/organizations/current", token, "", "").Code; code != 401 {
		t.Fatal("the revoked member reads after the reconciliation", code)
	}
	if !scalar[bool](t, l, `SELECT EXISTS(SELECT 1 FROM revocation_catalogue WHERE subject=$1)`, subject) {
		t.Fatal("the revocation subject was not copied back")
	}
	if r.SubjectsCopied != 1 {
		t.Fatal("the subjects copied", r.SubjectsCopied)
	}
	if !slices.Equal(r.DeletionsResumed, []string{sealed}) ||
		scalar[string](t, l, `SELECT phase FROM agents WHERE id=$1`, sealed) != "QUIESCING" ||
		scalar[string](t, l, `SELECT requested_by FROM deletion_operations WHERE agent_id=$1`, sealed) != "authority-reconciliation" {
		t.Fatal("the sealed agent's deletion was not resumed", r.DeletionsResumed)
	}
	if len(r.Divergent) != 1 || r.Divergent[0] != (controlplane.StoreDivergence{Store: restored, Reason: controlplane.DivergenceIncarnation, Authority: 2, Database: 1}) {
		t.Fatal("the restored store was not reported", r.Divergent)
	}
	if code, mode := readiness(t, l, p); code != 200 || mode != "standalone" {
		t.Fatal("the readiness after the reconciliation", code, mode)
	}
	// Repeated: nothing more to replay, the same report.
	again := reconcile(t, l, p)
	if again.Replayed != 0 || len(again.DeletionsResumed) != 0 || !slices.Equal(again.Divergent, r.Divergent) {
		t.Fatal("a repeated reconciliation", again)
	}
	report := scalar[[]byte](t, l, `SELECT report FROM authority_reconciliations WHERE epoch=2`)
	var stored struct {
		Divergent []controlplane.StoreDivergence `json:"divergent_stores"`
	}
	if err := json.Unmarshal(report, &stored); err != nil || !slices.Equal(stored.Divergent, r.Divergent) {
		t.Fatal("the recorded report", string(report), err)
	}
}

// restoreWitnessEarlyOpenGuard:
// init.then(revokeAccess(1)).then(losePrimary).then(promote).then(openApi.fail()).
// A membership revoked after the last WAL shipment: after the promotion the
// database lacks it, and the API does not open until the reconciliation.
func TestEarlyOpenGuard(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	a := newReplicatedAuthority(t)
	l.store.RecordAccessWith(a.api)
	member := apiAddMember(t, l, owner, "early-leaver", "agent_user")
	token := l.sign(t, at, "early-leaver-token", "early-leaver", allAgentScopes)
	grant := revokeMember(t, l, owner, member.PrincipalID)
	setBackMember(t, l, member.PrincipalID, grant)
	p := a.failover(t, a.lastContact(t).Add(time.Second))
	if code := call(t, l.server, "GET", "/v1/organizations/current", token, "", "").Code; code != 200 {
		t.Fatal("the set-back database does not revive the member: the guard is not exercised", code)
	}
	if err := l.store.CheckReconciled(t.Context(), 2); !errors.Is(err, controlplane.ErrNotReconciled) {
		t.Fatal("openApi did not fail", err)
	}
	if code, problem := readiness(t, l, p); code != 503 || problem != "authority_not_reconciled" {
		t.Fatal("the readiness", code, problem)
	}
	// Epoch 1, never promoted, counts as reconciled from the start.
	if err := l.store.CheckReconciled(t.Context(), 1); err != nil {
		t.Fatal("epoch 1", err)
	}
}

// shippedDatabaseNeedsNoReportTest:
// init.then(revokeAccess(1)).then(beginRestore(1)).then(shipWal).then(failover)
// .then(reconcileDatabase).then(openApi). The WAL shipped the revocation and
// the restore: the database and the authority agree, nothing is replayed,
// and no store is reported.
func TestShippedDatabaseNeedsNoReport(t *testing.T) {
	l, _, owner := apiAgentsLab(t)
	a := newReplicatedAuthority(t)
	l.store.RecordAccessWith(a.api)
	ctx := t.Context()
	member := apiAddMember(t, l, owner, "shipped-leaver", "agent_user")
	agent := apiTenantAgent(t, l, owner, "shipped")
	b := liveStore(t, l, a, agent)
	revokeMember(t, l, owner, member.PrincipalID)
	// beginRestore(1), on both sides: the authority's reservation, and the
	// database's restore at the next incarnation.
	if _, err := a.catalog.ReserveIncarnation(ctx, b, "restore-shipped"); err != nil {
		t.Fatal(err)
	}
	execSQL(t, l, `UPDATE store_enrollments SET stage='FENCING',volume_device='0000000000000001',volume_inode='0000000000000001' WHERE agent_id=$1`, agent)
	execSQL(t, l, `UPDATE store_enrollments SET stage='READY' WHERE agent_id=$1`, agent)
	execSQL(t, l, `INSERT INTO volume_restores(restore_id,agent_id,host_id,volume_id,archive_id,from_incarnation,incarnation)
        VALUES('rst_`+"00000000000000000000000000000001"+`',$1,'local',$2,'arc_`+"00000000000000000000000000000001"+`',1,2)`, agent, b.Volume)
	execSQL(t, l, `UPDATE store_enrollments SET stage='RESTORING',incarnation=2 WHERE agent_id=$1`, agent)
	p := a.failover(t, a.lastContact(t).Add(time.Second))
	r := reconcile(t, l, p)
	if r.Replayed != 0 || r.Kept != 0 || len(r.Divergent) != 0 || len(r.DeletionsResumed) != 0 || len(r.Unresumed) != 0 {
		t.Fatal("a shipped database needed something", r)
	}
	if code, mode := readiness(t, l, p); code != 200 || mode != "standalone" {
		t.Fatal("the readiness", code, mode)
	}
}

// shippedGrantRevocationSurvivesTest (module
// restoreAuthorityDecidedDegradedTests):
// init.then(degrade).then(revokeAccess(1)).then(shipWal).then(failover)
// .then(reconcileDatabase).then(openApi). A member revoked in degraded mode:
// the record is on the primary only, pending, and lost with it; PostgreSQL's
// WAL shipped the revocation. The reconciliation keeps it in the authority,
// and the member stays revoked.
func TestShippedGrantRevocationSurvives(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	a := newReplicatedAuthority(t)
	l.store.RecordAccessWith(a.api)
	member := apiAddMember(t, l, owner, "shipped-grant", "agent_user")
	token := l.sign(t, at, "shipped-grant-token", "shipped-grant", allAgentScopes)
	a.degrade(t)
	grant := revokeMember(t, l, owner, member.PrincipalID)
	if grant.State != controlplane.RevocationPending || a.held(t)[grant.ID] {
		t.Fatal("the revocation reached the replica", grant)
	}
	p := a.failover(t, a.lastContact(t).Add(authoritylog.DefaultDegradedAfter+time.Second))
	if records, err := p.catalog.AccessRecords(t.Context()); err != nil || slices.ContainsFunc(records, func(r restoreauthority.AccessRecord) bool { return r.ID == grant.ID }) {
		t.Fatal("the promoted authority holds the lost record", records, err)
	}
	r := reconcile(t, l, p)
	if r.Kept != 1 {
		t.Fatal("PostgreSQL's own revocation was not kept in the authority", r)
	}
	records, err := p.catalog.AccessRecords(t.Context())
	if err != nil || !slices.ContainsFunc(records, func(r restoreauthority.AccessRecord) bool {
		return r.ID == grant.ID && r.Kind == "member" && r.Objects[0][0] == member.PrincipalID
	}) {
		t.Fatal("the authority lacks the shipped revocation", records, err)
	}
	if status := scalar[string](t, l, `SELECT status FROM memberships WHERE principal_id=$1`, member.PrincipalID); status != "revoked" {
		t.Fatal("the shipped revocation was undone", status)
	}
	if code := call(t, l.server, "GET", "/v1/organizations/current", token, "", "").Code; code != 401 {
		t.Fatal("the revoked member reads after the failover", code)
	}
}

// tokenRevocationCoveredByBlanketTest:
// init.then(degrade).then(revokeAccess(0)).then(failover)
// .then(reconcileDatabase).then(openApi). A service token is revoked in
// degraded mode and confirmed at once; its record and PostgreSQL's commit
// are both lost with the primary. The standby's last contact is older than
// the degraded delay at the failover: the promotion writes the blanket
// revocation, and the reconciliation revokes every bearer token issued before
// the failover, the lost one included, moves the delegation trusts'
// minimum_iat past it, and records the announced window.
func TestTokenRevocationCoveredByBlanket(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	a := newReplicatedAuthority(t)
	l.store.RecordAccessWith(a.api)
	var account controlplane.ServiceAccount
	if r := call(t, l.server, "POST", "/v1/service-accounts", owner, "blanket-bot", `{"name":"bot","role":"agent_user"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &account) != nil {
		t.Fatal(r.Code, r.Body.String())
	}
	issue := func(key string) controlplane.IssuedServiceToken {
		var issued controlplane.IssuedServiceToken
		expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		if r := call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens", owner, key, `{"scopes":["org:read"],"expires_at":"`+expires+`"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &issued) != nil {
			t.Fatal(r.Code, r.Body.String())
		}
		return issued
	}
	revoked, kept := issue("blanket-revoked"), issue("blanket-kept")
	if code := call(t, l.server, "GET", "/v1/organizations/current", kept.Token, "", "").Code; code != 200 {
		t.Fatal("the token does not read before", code)
	}
	a.degrade(t)
	r := call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens/"+revoked.ID+"/revoke", owner, "blanket-revoke", `{}`)
	bearer := revocationsOf(t, r.Body.Bytes())
	if r.Code != 200 || len(bearer) != 1 || bearer[0].State != controlplane.RevocationConfirmed || a.held(t)[bearer[0].ID] {
		t.Fatal("the token's revocation in degraded mode", r.Code, r.Body.String())
	}
	// Lost with the primary: the record, and PostgreSQL's commit.
	execSQL(t, l, `UPDATE service_tokens SET revoked_at=NULL,revoked_by=NULL WHERE id=$1`, revoked.ID)
	forget(t, l, bearer[0].ID)
	if code := call(t, l.server, "GET", "/v1/organizations/current", revoked.Token, "", "").Code; code != 200 {
		t.Fatal("the set-back database does not revive the token: the run is not exercised", code)
	}
	contact := a.lastContact(t)
	failover := contact.Add(authoritylog.DefaultDegradedAfter + time.Second)
	p := a.failover(t, failover)
	announced := p.promotion.Announcement
	if !announced.Degraded || !announced.LastContact.Equal(contact) || !announced.Failover.Equal(failover) {
		t.Fatal("the promotion did not assume a degraded period", announced)
	}
	res := reconcile(t, l, p)
	if res.Announcement == nil || !res.Announcement.From.Equal(contact) || !res.Announcement.To.Equal(failover) || res.Announcement.Blanket != announced.Blanket {
		t.Fatal("the announced window", res.Announcement)
	}
	for _, token := range []string{revoked.Token, kept.Token, owner} {
		if code := call(t, l.server, "GET", "/v1/organizations/current", token, "", "").Code; code != 401 {
			t.Fatal("a bearer token issued before the failover reads after it", code)
		}
	}
	if !scalar[bool](t, l, `SELECT revoked_at IS NOT NULL FROM service_tokens WHERE id=$1`, revoked.ID) {
		t.Fatal("the lost token revocation is not covered")
	}
	// The delegation trusts take tokens from the second after the
	// failover: an iat is a whole second.
	if !scalar[bool](t, l, `SELECT bool_and(minimum_iat=date_trunc('second',$1::timestamptz)+interval '1 second') FROM delegation_trusts`, failover) || !at.Before(failover) {
		t.Fatal("a delegation trust still takes tokens issued before the failover")
	}
	if !scalar[bool](t, l, `SELECT degraded AND blanket_revocation_id=$1 AND window_from=$2 AND window_to=$3 FROM authority_reconciliations WHERE epoch=2`,
		announced.Blanket, contact, failover) {
		t.Fatal("the reconciliation did not record the announcement")
	}
	// The platform operator's credential went with the blanket too: a new
	// one, issued after the failover, reads the blanket revocation.
	if code := call(t, l.server, "GET", "/v1/organizations?limit=1", l.platform, "", "").Code; code != 401 {
		t.Fatal("the platform credential issued before the failover reads after it", code)
	}
	platform := platformForAPI(t, l.store)
	v := call(t, l.server, "GET", "/v1/access-revocations/"+announced.Blanket, platform, "", "")
	var blanket controlplane.AccessRevocation
	if v.Code != 200 || json.Unmarshal(v.Body.Bytes(), &blanket) != nil || blanket.Kind != "blanket" || blanket.State != controlplane.RevocationConfirmed {
		t.Fatal("the blanket revocation, as the platform operator reads it", v.Code, v.Body.String())
	}
}
