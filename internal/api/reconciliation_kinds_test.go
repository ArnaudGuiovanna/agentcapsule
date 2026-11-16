//go:build linux && cgo

package api

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5/pgxpool"
)

// replayAuthority stands for the promoted authority in
// TestReconciliationReplaysEveryRevokingRoute: it exports the records the
// revoking routes appended, and keeps what the reconciliation writes back.
type replayAuthority struct {
	records []controlplane.AccessRecord
	kept    []controlplane.AccessRecord
}

func (r *replayAuthority) RecordAccess(_ context.Context, rec controlplane.AccessRecord) (controlplane.AccessReceipt, error) {
	r.kept = append(r.kept, rec)
	return controlplane.AccessReceipt{Known: true, Epoch: 2, OnReplica: true}, nil
}

func (r *replayAuthority) AccessProgress(context.Context, string) (controlplane.AccessReceipt, error) {
	return controlplane.AccessReceipt{Known: true, Epoch: 2, OnReplica: true}, nil
}

func (r *replayAuthority) AuthorityEpoch(context.Context) (string, uint64, error) {
	return "restoreauth_" + strings.Repeat("e", 32), 2, nil
}

func (r *replayAuthority) AuthorityRecords(context.Context) ([]controlplane.AuthorityRecord, error) {
	var out []controlplane.AuthorityRecord
	for i, rec := range r.records {
		out = append(out, controlplane.AuthorityRecord{AccessRecord: rec, RecordedAt: time.Now(), Epoch: 1, Seq: uint64(i + 1), OnReplica: true})
	}
	return out, nil
}

func (r *replayAuthority) AuthoritySubjects(context.Context) ([]string, error) { return nil, nil }
func (r *replayAuthority) AuthorityStores(context.Context) ([]controlplane.AuthorityStore, error) {
	return nil, nil
}
func (r *replayAuthority) AuthorityAnnouncement(context.Context) (controlplane.FailoverAnnouncement, error) {
	return controlplane.FailoverAnnouncement{Epoch: 2}, nil
}
func (r *replayAuthority) ImportSubjects(context.Context, []string) error { return nil }

// accessState is what grants access in each table a revocation changes,
// one line per row.
func accessState(t *testing.T, db *pgxpool.Pool) []string {
	t.Helper()
	var out []string
	for _, q := range []string{
		`SELECT 'membership '||principal_id||' '||status FROM memberships`,
		`SELECT 'team_membership '||team_id||' '||principal_id||' '||status FROM team_memberships`,
		`SELECT 'principal '||id||' '||status FROM principals`,
		`SELECT 'team '||id||' '||status FROM teams`,
		`SELECT 'service_token '||id||' '||(revoked_at IS NULL) FROM service_tokens`,
		`SELECT 'assignment '||id||' '||status FROM agent_assignments`,
		`SELECT 'llm_provider '||id||' '||status||' '||secret_generation FROM llm_providers`,
		`SELECT 'organization '||id||' '||status FROM organizations`,
		`SELECT 'delegated_token '||issuer||' '||token_id FROM delegation_revocations`,
		`SELECT 'delegation_trust '||tenant_id||' '||audience||' '||status FROM delegation_trusts`,
		`SELECT 'platform_credential '||id||' '||(revoked_at IS NULL) FROM platform_credentials`,
	} {
		rows, err := db.Query(t.Context(), q)
		if err != nil {
			t.Fatal(q, err)
		}
		for rows.Next() {
			var line string
			if err = rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			out = append(out, line)
		}
		rows.Close()
	}
	slices.Sort(out)
	return out
}

// Every kind of record the revoking routes append replays its route's
// effect: a database set back to before them, reconciled, revokes again what
// they revoked, and nothing else. A rotated LLM provider is the one
// difference, by design: the set-back database holds the revoked credential
// and not the new one, so the provider is disabled.
func TestReconciliationReplaysEveryRevokingRoute(t *testing.T) {
	l, _, owner, fake, db := revocationLab(t)
	ctx := t.Context()
	must := func(method, path, key, body string, want int, v any) {
		t.Helper()
		r := call(t, l.server, method, path, owner, key, body)
		if r.Code != want || (v != nil && json.Unmarshal(r.Body.Bytes(), v) != nil) {
			t.Fatal(method, path, r.Code, r.Body.String())
		}
	}
	leaver := apiAddMember(t, l, owner, "kinds-leaver", "agent_user")
	teamMember := apiAddMember(t, l, owner, "kinds-team-member", "agent_user")
	assigned := apiAddMember(t, l, owner, "kinds-assigned", "agent_user")
	var team, disabled controlplane.Team
	must("POST", "/v1/teams", "kinds-team", `{"name":"kinds team"}`, 201, &team)
	must("POST", "/v1/teams/"+team.ID+"/members", "kinds-team-add", teamMemberBody(teamMember.PrincipalID), 201, nil)
	must("POST", "/v1/teams", "kinds-disabled", `{"name":"kinds disabled"}`, 201, &disabled)
	must("POST", "/v1/teams/"+disabled.ID+"/members", "kinds-disabled-add", teamMemberBody(assigned.PrincipalID), 201, nil)
	var account, spare controlplane.ServiceAccount
	must("POST", "/v1/service-accounts", "kinds-account", `{"name":"kinds bot","role":"agent_user"}`, 201, &account)
	must("POST", "/v1/service-accounts", "kinds-spare", `{"name":"kinds spare","role":"agent_user"}`, 201, &spare)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	var accountToken, spareToken controlplane.IssuedServiceToken
	must("POST", "/v1/service-accounts/"+account.ID+"/tokens", "kinds-account-token", `{"scopes":["org:read"],"expires_at":"`+expires+`"}`, 201, &accountToken)
	must("POST", "/v1/service-accounts/"+spare.ID+"/tokens", "kinds-spare-token", `{"scopes":["org:read"],"expires_at":"`+expires+`"}`, 201, &spareToken)
	agent := apiTenantAgent(t, l, owner, "kinds-agent")
	var assignment struct {
		ID string `json:"id"`
	}
	must("POST", "/v1/agents/"+agent+"/assignments", "kinds-assign", `{"principal_id":"`+assigned.PrincipalID+`","permissions":["read_metadata"]}`, 201, &assignment)
	var disabledProvider, rotatedProvider struct {
		ID string `json:"id"`
	}
	provider := `{"name":"%s","kind":"openai_compatible","base_url":"https://llm.example.org/v1","secret":"kinds-credential-0123456789"}`
	must("POST", "/v1/llm/providers", "kinds-provider-1", strings.Replace(provider, "%s", "disabled", 1), 201, &disabledProvider)
	must("POST", "/v1/llm/providers", "kinds-provider-2", strings.Replace(provider, "%s", "rotated", 1), 201, &rotatedProvider)
	var other controlplane.CreateOrganizationResponse
	if r := call(t, l.server, "POST", "/v1/organizations", l.platform, "kinds-org",
		`{"name":"Kinds disabled","initial_owner":{"issuer":"https://client.example","subject":"zoe","display_name":"Zoe"}}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &other) != nil {
		t.Fatal(r.Code, r.Body.String())
	}
	before := accessState(t, db)
	if _, err := db.Exec(ctx, `CREATE TABLE b_memberships AS SELECT * FROM memberships; CREATE TABLE b_team_memberships AS SELECT * FROM team_memberships;
        CREATE TABLE b_principals AS SELECT * FROM principals; CREATE TABLE b_teams AS SELECT * FROM teams;
        CREATE TABLE b_service_tokens AS SELECT * FROM service_tokens; CREATE TABLE b_agent_assignments AS SELECT * FROM agent_assignments;
        CREATE TABLE b_llm_providers AS SELECT * FROM llm_providers; CREATE TABLE b_llm_model_aliases AS SELECT * FROM llm_model_aliases;
        CREATE TABLE b_organizations AS SELECT * FROM organizations; CREATE TABLE b_delegation_trusts AS SELECT * FROM delegation_trusts;
        CREATE TABLE b_delegation_revocations AS SELECT * FROM delegation_revocations; CREATE TABLE b_platform_credentials AS SELECT * FROM platform_credentials`); err != nil {
		t.Fatal(err)
	}

	// Every revoking route, and the operator's commands.
	must("POST", "/v1/members/"+leaver.PrincipalID+"/revoke", "kinds-revoke-member", `{}`, 200, nil)
	must("POST", "/v1/teams/"+team.ID+"/members/"+teamMember.PrincipalID+"/revoke", "kinds-revoke-team-member", `{}`, 200, nil)
	must("POST", "/v1/teams/"+disabled.ID+"/disable", "kinds-disable-team", `{}`, 200, nil)
	must("POST", "/v1/service-accounts/"+account.ID+"/tokens/"+accountToken.ID+"/revoke", "kinds-revoke-token", `{}`, 200, nil)
	must("POST", "/v1/service-accounts/"+spare.ID+"/disable", "kinds-disable-account", `{}`, 200, nil)
	must("POST", "/v1/agents/"+agent+"/assignments/"+assignment.ID+"/revoke", "kinds-revoke-assignment", `{}`, 200, nil)
	must("POST", "/v1/llm/providers/"+disabledProvider.ID+"/disable", "kinds-disable-provider", `{}`, 200, nil)
	must("POST", "/v1/llm/providers/"+rotatedProvider.ID+"/rotate", "kinds-rotate-provider", `{"secret":"kinds-credential-rotated-0123"}`, 200, nil)
	if r := call(t, l.server, "POST", "/v1/organizations/"+other.ID+"/disable", l.platform, "kinds-disable-org", `{}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	if _, err := l.store.ChangeDelegationAuthority(ctx, controlplane.DelegationChange{OperationID: "kinds-revoke-jwt", Actor: "test-operator",
		Action: "revoke-token", TenantID: l.org.ID, Issuer: l.trust.Issuer, TokenID: "kinds-jwt"}); err != nil {
		t.Fatal(err)
	}
	creds, err := l.store.ListOperatorCredentials(ctx)
	if err != nil || len(creds) == 0 {
		t.Fatal(creds, err)
	}
	if _, err = l.store.RevokeOperatorCredential(ctx, controlplane.OperatorCommand{Actor: "test-operator"}, "platform", creds[0].ID); err != nil {
		t.Fatal(err)
	}
	// Last: the owner signs in through this trust.
	if _, err = l.store.ChangeDelegationAuthority(ctx, controlplane.DelegationChange{OperationID: "kinds-revoke-trust", Actor: "test-operator",
		Action: "revoke-trust", TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience}); err != nil {
		t.Fatal(err)
	}
	after := accessState(t, db)
	records := fake.recorded()
	var kinds []string
	for _, r := range records {
		kinds = append(kinds, r.Kind)
	}
	slices.Sort(kinds)
	if strings.Join(slices.Compact(kinds), " ") != "assignment delegated_token delegation_trust llm_provider member organization platform_credential principal service_token team team_membership" {
		t.Fatal("the kinds recorded", kinds)
	}

	// The database set back to before the revocations.
	if _, err = db.Exec(ctx, `UPDATE memberships m SET status=b.status FROM b_memberships b WHERE (m.tenant_id,m.principal_id)=(b.tenant_id,b.principal_id);
        UPDATE team_memberships m SET status=b.status FROM b_team_memberships b WHERE (m.tenant_id,m.team_id,m.principal_id)=(b.tenant_id,b.team_id,b.principal_id);
        UPDATE principals m SET status=b.status FROM b_principals b WHERE m.id=b.id;
        UPDATE teams m SET status=b.status FROM b_teams b WHERE m.id=b.id;
        UPDATE service_tokens m SET revoked_at=b.revoked_at,revoked_by=b.revoked_by FROM b_service_tokens b WHERE m.id=b.id;
        UPDATE agent_assignments m SET status=b.status,revoked_at=b.revoked_at,revoked_by=b.revoked_by FROM b_agent_assignments b WHERE m.id=b.id;
        UPDATE llm_providers m SET status=b.status,disabled_at=b.disabled_at,secret_ciphertext=b.secret_ciphertext,secret_generation=b.secret_generation
          FROM b_llm_providers b WHERE m.id=b.id;
        UPDATE llm_model_aliases m SET status=b.status,disabled_at=b.disabled_at FROM b_llm_model_aliases b WHERE (m.tenant_id,m.alias)=(b.tenant_id,b.alias);
        UPDATE organizations m SET status=b.status FROM b_organizations b WHERE m.id=b.id;
        DELETE FROM delegation_revocations m WHERE NOT EXISTS(SELECT 1 FROM b_delegation_revocations b WHERE (b.tenant_id,b.issuer,b.token_id)=(m.tenant_id,m.issuer,m.token_id));
        UPDATE platform_credentials m SET revoked_at=b.revoked_at FROM b_platform_credentials b WHERE m.id=b.id;
        UPDATE delegation_trusts m SET status=b.status FROM b_delegation_trusts b WHERE (m.tenant_id,m.issuer,m.audience)=(b.tenant_id,b.issuer,b.audience);
        ALTER TABLE access_revocations DISABLE TRIGGER access_revocation_guard; DELETE FROM access_revocations;
        ALTER TABLE access_revocations ENABLE TRIGGER access_revocation_guard`); err != nil {
		t.Fatal(err)
	}
	if got := accessState(t, db); !slices.Equal(got, before) {
		t.Fatal("the database was not set back", got)
	}

	authority := &replayAuthority{records: records}
	r, err := l.store.Reconcile(ctx, authority)
	if err != nil || r.Replayed != len(records) || len(authority.kept) != 0 {
		t.Fatal("the reconciliation", r, err, authority.kept)
	}
	replayed := accessState(t, db)
	rotated := "llm_provider " + rotatedProvider.ID
	for i, line := range after {
		if strings.HasPrefix(line, rotated+" ") {
			after[i] = rotated + " disabled 1"
		}
	}
	slices.Sort(after)
	if !slices.Equal(replayed, after) {
		t.Fatalf("the replay differs from the routes\nroutes:   %v\nreplayed: %v", after, replayed)
	}
	if n := scalar[int](t, l, `SELECT count(*) FROM access_revocations`); n != len(records) {
		t.Fatal("the replayed revocations' rows", n)
	}
	// Run again: every record is held now, nothing is replayed.
	if again, err := l.store.Reconcile(ctx, authority); err != nil || again.Replayed != 0 {
		t.Fatal("run again", again, err)
	}
}
