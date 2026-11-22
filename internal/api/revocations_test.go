package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeAuthority stands for the authority service's access revocation
// records (ADR 006 wave 5): it keeps every record it is given, answers as
// the test says, and runs during, if set, while it records.
type fakeAuthority struct {
	mu        sync.Mutex
	records   []controlplane.AccessRecord
	known     map[string]bool
	fail      error
	onReplica bool
	degraded  bool
	during    func(controlplane.AccessRecord)
}

func (f *fakeAuthority) RecordAccess(_ context.Context, r controlplane.AccessRecord) (controlplane.AccessReceipt, error) {
	f.mu.Lock()
	during, fail := f.during, f.fail
	f.mu.Unlock()
	if during != nil {
		during(r)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if fail != nil {
		return controlplane.AccessReceipt{}, fail
	}
	if f.known == nil {
		f.known = map[string]bool{}
	}
	f.known[r.ID] = true
	f.records = append(f.records, r)
	return controlplane.AccessReceipt{Known: true, Epoch: 1, Seq: uint64(len(f.records)), OnReplica: f.onReplica, Degraded: f.degraded}, nil
}

func (f *fakeAuthority) AccessProgress(_ context.Context, id string) (controlplane.AccessReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return controlplane.AccessReceipt{}, f.fail
	}
	return controlplane.AccessReceipt{Known: f.known[id], Epoch: 1, OnReplica: f.onReplica, Degraded: f.degraded}, nil
}

func (f *fakeAuthority) set(onReplica, degraded bool, fail error) {
	f.mu.Lock()
	f.onReplica, f.degraded, f.fail = onReplica, degraded, fail
	f.mu.Unlock()
}

func (f *fakeAuthority) recorded() []controlplane.AccessRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]controlplane.AccessRecord(nil), f.records...)
}

// revocationsOf reads the revocations of a revoking route's answer.
func revocationsOf(t *testing.T, body []byte) []controlplane.AccessRevocation {
	t.Helper()
	var answer struct {
		Revocations []controlplane.AccessRevocation `json:"revocations"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		t.Fatal(err, string(body))
	}
	return answer.Revocations
}

// revocationLab is apiAgentsLab with a fake authority service, and a pool
// that reads PostgreSQL beside the API, as another connection does.
func revocationLab(t *testing.T) (*apiDelegationFixture, time.Time, string, *fakeAuthority, *pgxpool.Pool) {
	t.Helper()
	l, at, owner := apiAgentsLab(t)
	db, err := pgxpool.New(t.Context(), l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	fake := &fakeAuthority{onReplica: true}
	l.store.RecordAccessWith(fake)
	return l, at, owner, fake, db
}

// Every revoking transaction appends its record to the authority service
// once it has committed (ADR 006, "Changes after the v0.1.0 audit"): while
// the service records it, the member is already revoked in PostgreSQL, and
// neither the organization's row nor the shared gate is held, so a slow
// service stalls no other request of the organization. The record names its
// kind, the organization and the member; the answer reports it confirmed
// once the replica holds it, and a replay says the same.
func TestRevocationRecordsItsRecordAfterItsCommitWithNoLockHeld(t *testing.T) {
	l, _, owner, fake, db := revocationLab(t)
	target := apiAddMember(t, l, owner, "leaver", "agent_user")
	var before []string
	fake.during = func(r controlplane.AccessRecord) {
		ctx := context.Background()
		var status string
		if err := db.QueryRow(ctx, `SELECT status FROM memberships WHERE principal_id=$1`, target.PrincipalID).Scan(&status); err != nil {
			t.Error(err)
		}
		before = append(before, status)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		defer tx.Rollback(ctx)
		var gate bool
		if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended(current_schema()::text,756610045))`).Scan(&gate); err != nil || !gate {
			t.Error("the shared gate is held while the service records", gate, err)
		}
		if _, err = tx.Exec(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE NOWAIT`, l.org.ID); err != nil {
			t.Error("the organization's row is locked while the service records:", err)
		}
	}
	r := call(t, l.server, "POST", "/v1/members/"+target.PrincipalID+"/revoke", owner, "revoke-leaver", `{}`)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	records := fake.recorded()
	if len(records) != 1 || records[0].Kind != "member" || records[0].Organization != l.org.ID ||
		len(records[0].Objects) != 1 || records[0].Objects[0][0] != target.PrincipalID || !strings.HasPrefix(records[0].ID, "arv_") {
		t.Fatal("the record", records)
	}
	if fmt.Sprint(before) != "[revoked]" {
		t.Fatal("the record did not follow the commit", before)
	}
	revocations := revocationsOf(t, r.Body.Bytes())
	if len(revocations) != 1 || revocations[0].ID != records[0].ID || revocations[0].Kind != "member" ||
		revocations[0].State != controlplane.RevocationConfirmed || revocations[0].ConfirmedAt == nil {
		t.Fatal("the answer", r.Body.String())
	}
	var m controlplane.Member
	if err := json.Unmarshal(r.Body.Bytes(), &m); err != nil || m.Status != "revoked" || m.PrincipalID != target.PrincipalID {
		t.Fatal("the member in the answer", m, err)
	}
	replay := call(t, l.server, "POST", "/v1/members/"+target.PrincipalID+"/revoke", owner, "revoke-leaver", `{}`)
	if replay.Code != 200 || replay.Body.String() != r.Body.String() || len(fake.recorded()) != 1 {
		t.Fatal("the replay", replay.Code, replay.Body.String())
	}
}

// A revocation takes effect while the authority service does not answer
// (fail closed): the member loses access at once, the answer says the
// revocation is recording, and the API records it once the service answers
// again, without another request. The revocation's resource and a replay
// give its current state.
func TestRevocationTakesEffectWhileTheAuthorityServiceIsDown(t *testing.T) {
	l, at, owner, fake, db := revocationLab(t)
	target := apiAddMember(t, l, owner, "stays", "agent_user")
	token := l.sign(t, at, "stays-token", "stays", allAgentScopes)
	fake.set(false, false, errors.New("the authority service does not answer"))
	r := call(t, l.server, "POST", "/v1/members/"+target.PrincipalID+"/revoke", owner, "revoke-stays", `{}`)
	revoked := revocationsOf(t, r.Body.Bytes())
	if r.Code != 200 || len(revoked) != 1 || revoked[0].State != controlplane.RevocationRecording || revoked[0].ConfirmedAt != nil {
		t.Fatal("a revocation the service did not record", r.Code, r.Body.String())
	}
	if call(t, l.server, "GET", "/v1/organizations/current", token, "", "").Code != 401 {
		t.Fatal("the revoked member kept access while the service is down")
	}
	if len(fake.recorded()) != 0 {
		t.Fatal("the service recorded it", fake.recorded())
	}
	if n, _, err := l.store.UnrecordedAccessRevocations(t.Context()); err != nil || n != 1 {
		t.Fatal("unrecorded revocations", n, err)
	}
	if n, err := l.store.ConfirmAccessRevocations(t.Context(), 100); err != nil || n != 0 {
		t.Fatal("recorded while the service is down", n, err)
	}
	// The service answers again: the next pass records it.
	fake.set(true, false, nil)
	if n, err := l.store.ConfirmAccessRevocations(t.Context(), 100); err != nil || n != 1 {
		t.Fatal("not recorded once the service answers", n, err)
	}
	records := fake.recorded()
	if len(records) != 1 || records[0].ID != revoked[0].ID || records[0].Kind != "member" || records[0].Organization != l.org.ID ||
		records[0].Objects[0][0] != target.PrincipalID {
		t.Fatal("the record", records)
	}
	var state string
	var epoch, seq *int64
	if err := db.QueryRow(t.Context(), `SELECT state,epoch,seq FROM access_revocations WHERE id=$1`, revoked[0].ID).Scan(&state, &epoch, &seq); err != nil ||
		state != controlplane.RevocationConfirmed || epoch == nil || *epoch != 1 || seq == nil || *seq != 1 {
		t.Fatal("the row", state, epoch, seq, err)
	}
	again := call(t, l.server, "POST", "/v1/members/"+target.PrincipalID+"/revoke", owner, "revoke-stays", `{}`)
	if now := revocationsOf(t, again.Body.Bytes()); again.Code != 200 || again.Header().Get("Idempotency-Replayed") != "true" ||
		len(now) != 1 || now[0].State != controlplane.RevocationConfirmed {
		t.Fatal("the replay", again.Code, again.Body.String())
	}
	// Recorded twice changes nothing: the next pass finds nothing to record.
	if n, err := l.store.ConfirmAccessRevocations(t.Context(), 100); err != nil || n != 0 || len(fake.recorded()) != 1 {
		t.Fatal("recorded again", n, err)
	}
	if n, _, err := l.store.UnrecordedAccessRevocations(t.Context()); err != nil || n != 0 {
		t.Fatal("unrecorded revocations", n, err)
	}
}

// A revoking transaction that rolls back leaves no record in the authority
// service: no later reconciliation can replay a revocation PostgreSQL never
// made. Here its audit row fails, after the revocation's row.
func TestRolledBackRevocationLeavesNoRecord(t *testing.T) {
	l, at, owner, fake, db := revocationLab(t)
	target := apiAddMember(t, l, owner, "kept", "agent_user")
	token := l.sign(t, at, "kept-token", "kept", allAgentScopes)
	if _, err := db.Exec(t.Context(), `CREATE FUNCTION refuse_member_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'audit refused by the test'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), `CREATE TRIGGER refuse_member_audit BEFORE INSERT ON tenant_member_audit
        FOR EACH ROW EXECUTE FUNCTION refuse_member_audit()`); err != nil {
		t.Fatal(err)
	}
	r := call(t, l.server, "POST", "/v1/members/"+target.PrincipalID+"/revoke", owner, "revoke-kept", `{}`)
	if r.Code < 500 {
		t.Fatal("the revocation did not fail", r.Code, r.Body.String())
	}
	if len(fake.recorded()) != 0 {
		t.Fatal("a rolled-back revocation reached the authority service", fake.recorded())
	}
	var rows int
	if err := db.QueryRow(t.Context(), `SELECT count(*) FROM access_revocations`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("a revocation row without its transaction", rows, err)
	}
	if n, err := l.store.ConfirmAccessRevocations(t.Context(), 100); err != nil || n != 0 || len(fake.recorded()) != 0 {
		t.Fatal("a later pass recorded it", n, err)
	}
	if call(t, l.server, "GET", "/v1/organizations/current", token, "", "").Code != 200 {
		t.Fatal("the member lost access although nothing was committed")
	}
}

// Finding 1, option (a): a standing grant's revocation takes effect at once,
// and is pending until the replica holds its record; a bearer token's is
// confirmed at once in degraded mode. The state shows in the answer, in the
// revocation's own resource and in the metrics, and a replay gives the
// current state.
func TestRevocationIsPendingUntilTheReplicaHoldsIt(t *testing.T) {
	l, at, owner, fake, _ := revocationLab(t)
	registry := telemetry.NewRegistry()
	l.server.EnableTelemetry(registry, &strings.Builder{})
	scrape := func() string {
		w := httptest.NewRecorder()
		registry.Handler(5*time.Second).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		return w.Body.String()
	}
	target := apiAddMember(t, l, owner, "pending", "agent_user")
	token := l.sign(t, at, "pending-token", "pending", allAgentScopes)
	var account controlplane.ServiceAccount
	if r := call(t, l.server, "POST", "/v1/service-accounts", owner, "bot", `{"name":"bot","role":"agent_user"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &account) != nil {
		t.Fatal(r.Code, r.Body.String())
	}
	var issued controlplane.IssuedServiceToken
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if r := call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens", owner, "bot-token", `{"scopes":["org:read"],"expires_at":"`+expires+`"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &issued) != nil {
		t.Fatal(r.Code, r.Body.String())
	}

	fake.set(false, true, nil) // degraded mode
	r := call(t, l.server, "POST", "/v1/members/"+target.PrincipalID+"/revoke", owner, "revoke-pending", `{}`)
	grant := revocationsOf(t, r.Body.Bytes())
	if r.Code != 200 || len(grant) != 1 || grant[0].State != controlplane.RevocationPending || grant[0].ConfirmedAt != nil {
		t.Fatal("a standing grant's revocation in degraded mode", r.Code, r.Body.String())
	}
	if call(t, l.server, "GET", "/v1/organizations/current", token, "", "").Code != 401 {
		t.Fatal("a pending revocation did not take effect at once")
	}
	r = call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens/"+issued.ID+"/revoke", owner, "revoke-bot-token", `{}`)
	bearer := revocationsOf(t, r.Body.Bytes())
	if r.Code != 200 || len(bearer) != 1 || bearer[0].Kind != "service_token" || bearer[0].State != controlplane.RevocationConfirmed {
		t.Fatal("a bearer token's revocation in degraded mode", r.Code, r.Body.String())
	}
	read := func(token, id string) (int, controlplane.AccessRevocation) {
		t.Helper()
		r := call(t, l.server, "GET", "/v1/access-revocations/"+id, token, "", "")
		var v controlplane.AccessRevocation
		if r.Code == 200 {
			if err := json.Unmarshal(r.Body.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
		}
		return r.Code, v
	}
	if code, v := read(owner, grant[0].ID); code != 200 || v.State != controlplane.RevocationPending || v.Kind != "member" {
		t.Fatal("the pending revocation's resource", code, v)
	}
	if code, _ := read(l.platform, grant[0].ID); code != 404 {
		t.Fatal("the platform read an organization's revocation", code)
	}
	if !strings.Contains(scrape(), "agentcapsule_api_access_revocations_pending 1\n") {
		t.Fatal("the pending revocation is not in the metrics", scrape())
	}
	if n, err := l.store.ConfirmAccessRevocations(t.Context(), 100); err != nil || n != 0 {
		t.Fatal("confirmed while the replica lacks it", n, err)
	}

	// The standby holds it now.
	fake.set(true, false, nil)
	if n, err := l.store.ConfirmAccessRevocations(t.Context(), 100); err != nil || n != 1 {
		t.Fatal("not confirmed once on the replica", n, err)
	}
	if code, v := read(owner, grant[0].ID); code != 200 || v.State != controlplane.RevocationConfirmed || v.ConfirmedAt == nil {
		t.Fatal("the confirmed revocation's resource", code, v)
	}
	replay := call(t, l.server, "POST", "/v1/members/"+target.PrincipalID+"/revoke", owner, "revoke-pending", `{}`)
	if now := revocationsOf(t, replay.Body.Bytes()); replay.Code != 200 || replay.Header().Get("Idempotency-Replayed") != "true" ||
		len(now) != 1 || now[0].State != controlplane.RevocationConfirmed {
		t.Fatal("the replay gives the state of then", replay.Body.String())
	}
	if !strings.Contains(scrape(), "agentcapsule_api_access_revocations_pending 0\n") {
		t.Fatal("the metrics", scrape())
	}

	// Outside degraded mode, a record the replica does not hold yet is
	// pending, a bearer token's too; reading it asks the service again.
	fake.set(false, false, nil)
	second := apiAddMember(t, l, owner, "later", "agent_user")
	r = call(t, l.server, "POST", "/v1/members/"+second.PrincipalID+"/revoke", owner, "revoke-later", `{}`)
	later := revocationsOf(t, r.Body.Bytes())
	if r.Code != 200 || len(later) != 1 || later[0].State != controlplane.RevocationPending {
		t.Fatal(r.Code, r.Body.String())
	}
	fake.set(true, false, nil)
	if code, v := read(owner, later[0].ID); code != 200 || v.State != controlplane.RevocationConfirmed {
		t.Fatal("reading a pending revocation did not ask again", code, v)
	}
}
