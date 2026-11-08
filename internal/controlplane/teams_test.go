package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func teamLab(t *testing.T) (*tenantLab, Principal) {
	t.Helper()
	l := newTenantLab(t, false)
	l.trust.AllowedScopes = []string{"org:read", "member:read", "member:manage", "team:read", "team:manage"}
	var err error
	l.v, err = delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.cutoff = l.change(t, "install", "teams-install", "", &l.trust).MinimumIAT
	waitTenantClock(t, l.s, l.cutoff)
	return l, teamPrincipal(t, l, organizationInput().InitialOwner.Subject)
}
func teamPrincipal(t *testing.T, l *tenantLab, subject string) Principal {
	t.Helper()
	raw := l.sign(t, newID("jti"), l.cutoff, func(c jwt.MapClaims) {
		c["sub"] = subject
		c["scope"] = "org:read member:read member:manage team:read team:manage"
	})
	p, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func createTeam(t *testing.T, l *tenantLab, p Principal, key string) Team {
	t.Helper()
	r, err := l.a.CreateTeam(t.Context(), p, key, CreateTeamInput{Name: key})
	var team Team
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &team) != nil {
		t.Fatal("create team", err, r.Status)
	}
	return team
}
func teamMemberState(t *testing.T, l *tenantLab, team, member string) string {
	t.Helper()
	var status string
	if err := l.s.pool.QueryRow(t.Context(), `SELECT status FROM team_memberships WHERE tenant_id=$1 AND team_id=$2 AND principal_id=$3`, l.org.ID, team, member).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestTeamsHistoricalReplayNeverReactivatesMembershipOrTeam(t *testing.T) {
	l, owner := teamLab(t)
	member := addMember(t, l, owner, "human", authorization.AgentUser)
	team := createTeam(t, l, owner, "support")
	in := AddTeamMemberInput{PrincipalID: member.PrincipalID}
	first, err := l.a.AddTeamMember(t.Context(), owner, team.ID, "join", in)
	if err != nil || first.Status != 201 {
		t.Fatal(err)
	}
	if _, err = l.a.RevokeTeamMember(t.Context(), owner, team.ID, member.PrincipalID, "leave"); err != nil {
		t.Fatal(err)
	}
	audits := count(t, l.s, "tenant_team_audit")
	replayed, err := l.a.AddTeamMember(t.Context(), owner, team.ID, "join", in)
	if err != nil || !replayed.Replayed || string(replayed.Body) != string(first.Body) || teamMemberState(t, l, team.ID, member.PrincipalID) != "revoked" || count(t, l.s, "tenant_team_audit") != audits {
		t.Fatal("replay reactivated grant", err)
	}
	if r, err := l.a.AddTeamMember(t.Context(), owner, team.ID, "explicit-rejoin", in); err != nil || r.Status != 200 || r.Replayed {
		t.Fatal("explicit rejoin", err)
	}
	if teamMemberState(t, l, team.ID, member.PrincipalID) != "active" {
		t.Fatal("new grant missing")
	}
	// Adding the owner changes only team membership, never the organization role.
	if _, err := l.a.AddTeamMember(t.Context(), owner, team.ID, "owner-join", AddTeamMemberInput{owner.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.DisableTeam(t.Context(), owner, team.ID, "disable"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{owner.ID, member.PrincipalID} {
		if teamMemberState(t, l, team.ID, id) != "revoked" {
			t.Fatal("disable retained grant")
		}
	}
	for _, key := range []string{"join", "explicit-rejoin", "new-after-disable"} {
		if _, err := l.a.AddTeamMember(t.Context(), owner, team.ID, key, in); !errors.Is(err, ErrTransition) {
			t.Fatal("disabled team accepted addition/replay", key, err)
		}
	}
	r, err := l.a.CreateTeam(t.Context(), owner, "support", CreateTeamInput{"support"})
	if err != nil || !r.Replayed {
		t.Fatal("create replay", err)
	}
	current, err := l.a.GetTeam(t.Context(), owner, team.ID)
	if err != nil || current.Status != "disabled" {
		t.Fatal("create replay resurrected team", err)
	}
	var before, after int64
	if err = l.s.pool.QueryRow(t.Context(), `SELECT policy_version FROM organizations WHERE id=$1`, l.org.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.DisableTeam(t.Context(), owner, team.ID, "disabled-noop"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.RevokeTeamMember(t.Context(), owner, team.ID, member.PrincipalID, "already-removed"); err != nil {
		t.Fatal(err)
	}
	if err = l.s.pool.QueryRow(t.Context(), `SELECT policy_version FROM organizations WHERE id=$1`, l.org.ID).Scan(&after); err != nil || before != after {
		t.Fatal("noop policy change", err)
	}
	org, err := l.a.CurrentOrganization(t.Context(), owner)
	if err != nil || org.Role != "org_owner" {
		t.Fatal("team altered owner", err)
	}
	items, err := l.a.ListTeamMembers(t.Context(), owner, team.ID, "", 100)
	if err != nil || len(items) != 2 {
		t.Fatal("disabled metadata unavailable", err)
	}
}

func TestTeamsCurrentActorAndTargetCheckedBeforeReplay(t *testing.T) {
	l, owner := teamLab(t)
	admin := addMember(t, l, owner, "manager", authorization.OrgAdmin)
	actor := teamPrincipal(t, l, "manager")
	member := addMember(t, l, owner, "target", authorization.AgentUser)
	team := createTeam(t, l, actor, "managed")
	// A service principal is excluded even if legacy data gave it an active
	// organization membership. Team routes manage human memberships only.
	service := newID("prn")
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO principals(id,tenant_id,kind,display_name) VALUES($1,$2,'service','service')`, service, l.org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO memberships(tenant_id,principal_id,role) VALUES($1,$2,'agent_user')`, l.org.ID, service); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.AddTeamMember(t.Context(), actor, team.ID, "technical-target", AddTeamMemberInput{service}); !errors.Is(err, ErrNotFound) {
		t.Fatal("service target accepted", err)
	}
	in := AddTeamMemberInput{member.PrincipalID}
	if _, err := l.a.AddTeamMember(t.Context(), actor, team.ID, "join", in); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.RevokeMember(t.Context(), owner, member.PrincipalID, "offboard-target"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"join", "new"} {
		if _, err := l.a.AddTeamMember(t.Context(), actor, team.ID, key, in); !errors.Is(err, ErrTransition) {
			t.Fatal("revoked target accepted", err)
		}
	}
	if _, err := l.a.RevokeTeamMember(t.Context(), actor, team.ID, member.PrincipalID, "cleanup"); err != nil {
		t.Fatal("revoked target cleanup refused", err)
	}
	if _, err := l.a.ChangeMemberRole(t.Context(), owner, admin.PrincipalID, "demote", ChangeMemberRoleInput{authorization.AgentUser}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.CreateTeam(t.Context(), actor, "managed", CreateTeamInput{"managed"}); !errors.Is(err, ErrForbidden) {
		t.Fatal("stale role replay", err)
	}
	if _, err := l.a.GetTeam(t.Context(), actor, team.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("stale role read", err)
	}
	if _, err := l.a.RevokeMember(t.Context(), owner, admin.PrincipalID, "offboard-manager"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.DisableTeam(t.Context(), actor, team.ID, "stale"); !errors.Is(err, ErrAuthentication) {
		t.Fatal("stale principal mutation", err)
	}
}

func TestTeamsAuditAndReceiptFailureRollBackAllEffects(t *testing.T) {
	for _, failing := range []string{"tenant_team_audit", "tenant_http_receipts"} {
		t.Run(failing, func(t *testing.T) {
			l, owner := teamLab(t)
			member := addMember(t, l, owner, "target", authorization.AgentUser)
			team := createTeam(t, l, owner, "before")
			if _, err := l.a.AddTeamMember(t.Context(), owner, team.ID, "initial", AddTeamMemberInput{owner.ID}); err != nil {
				t.Fatal(err)
			}
			beforeAudit, beforeReceipts := count(t, l.s, "tenant_team_audit"), count(t, l.s, "tenant_http_receipts")
			var beforeVersion int64
			if err := l.s.pool.QueryRow(t.Context(), `SELECT policy_version FROM organizations WHERE id=$1`, l.org.ID).Scan(&beforeVersion); err != nil {
				t.Fatal(err)
			}
			if _, err := l.s.pool.Exec(t.Context(), `CREATE FUNCTION fail_team_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'unavailable'; END $$; CREATE TRIGGER fail_team_write BEFORE INSERT ON `+failing+` FOR EACH ROW EXECUTE FUNCTION fail_team_write()`); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"create", "add", "revoke", "disable"} {
				var err error
				switch operation {
				case "create":
					_, err = l.a.CreateTeam(t.Context(), owner, "fail", CreateTeamInput{"must rollback"})
				case "add":
					_, err = l.a.AddTeamMember(t.Context(), owner, team.ID, "fail", AddTeamMemberInput{member.PrincipalID})
				case "revoke":
					_, err = l.a.RevokeTeamMember(t.Context(), owner, team.ID, owner.ID, "fail")
				case "disable":
					_, err = l.a.DisableTeam(t.Context(), owner, team.ID, "fail")
				}
				if err == nil {
					t.Fatal("partial failure acknowledged", operation)
				}
				var version int64
				if err = l.s.pool.QueryRow(t.Context(), `SELECT policy_version FROM organizations WHERE id=$1`, l.org.ID).Scan(&version); err != nil {
					t.Fatal(err)
				}
				current, err := l.a.GetTeam(t.Context(), owner, team.ID)
				if err != nil || current.Status != "active" || version != beforeVersion || count(t, l.s, "teams") != 1 || count(t, l.s, "team_memberships") != 1 || count(t, l.s, "tenant_team_audit") != beforeAudit || count(t, l.s, "tenant_http_receipts") != beforeReceipts || teamMemberState(t, l, team.ID, owner.ID) != "active" {
					t.Fatal("partial commit", operation, err)
				}
			}
		})
	}
}

// Observe through a dedicated connection: a 4-connection application pool can
// legitimately be occupied by gate, mutation and two waiting requests.
func waitTeamBlockers(t *testing.T, s *Store, blocker uint32, minimum int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	c, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Close(closeCtx)
	}()
	waitMemberBlock(t, c, blocker, minimum)
}

func TestTeamsWaitingAddAndReplayObserveCommittedRevocation(t *testing.T) {
	for _, mode := range []string{"team", "target", "actor"} {
		t.Run(mode, func(t *testing.T) {
			l, owner := teamLab(t)
			manager := addMember(t, l, owner, "manager", authorization.OrgAdmin)
			actor := teamPrincipal(t, l, "manager")
			member := addMember(t, l, owner, "target", authorization.AgentUser)
			team := createTeam(t, l, actor, "team")
			in := AddTeamMemberInput{member.PrincipalID}
			if _, err := l.a.AddTeamMember(t.Context(), actor, team.ID, "join", in); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			poolConfig := l.s.pool.Config()
			poolConfig.MaxConns, poolConfig.MinConns = 4, 0
			pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
			if err != nil {
				t.Fatal(err)
			}
			l.s.pool.Close()
			l.s.pool = pool
			gate, err := l.s.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollback(gate)
			const gateKey int64 = 98765432101236
			if _, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, gateKey); err != nil {
				t.Fatal(err)
			}
			var gatePID uint32
			if err = gate.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&gatePID); err != nil {
				t.Fatal(err)
			}
			table, action := "tenant_member_audit", "member.revoked"
			if mode == "team" {
				table, action = "tenant_team_audit", "team.disabled"
			}
			if _, err = l.s.pool.Exec(ctx, `CREATE FUNCTION hold_team_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='`+action+`' THEN PERFORM pg_advisory_xact_lock(98765432101236::bigint); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_team_revocation BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION hold_team_revocation()`); err != nil {
				t.Fatal(err)
			}
			revoked := make(chan error, 1)
			go func() {
				var err error
				switch mode {
				case "team":
					_, err = l.a.DisableTeam(ctx, owner, team.ID, "disable")
				case "target":
					_, err = l.a.RevokeMember(ctx, owner, member.PrincipalID, "offboard")
				case "actor":
					_, err = l.a.RevokeMember(ctx, owner, manager.PrincipalID, "offboard")
				}
				revoked <- err
			}()
			finished := false
			defer func() {
				rollback(gate)
				cancel()
				if !finished {
					<-revoked
				}
			}()
			waitTeamBlockers(t, l.s, gatePID, 1)
			var revokePID uint32
			if err = gate.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, gatePID).Scan(&revokePID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 2)
			for _, key := range []string{"join", "new-after-revoke"} {
				go func(key string) { _, err := l.a.AddTeamMember(ctx, actor, team.ID, key, in); done <- err }(key)
			}
			consumed := 0
			defer func() {
				rollback(gate)
				cancel()
				for consumed < 2 {
					<-done
					consumed++
				}
			}()
			waitTeamBlockers(t, l.s, revokePID, 2)
			if err = commit(ctx, gate); err != nil {
				t.Fatal(err)
			}
			err = <-revoked
			finished = true
			if err != nil {
				t.Fatal(err)
			}
			want := ErrTransition
			if mode == "actor" {
				want = ErrAuthentication
			}
			for consumed < 2 {
				err = <-done
				consumed++
				if !errors.Is(err, want) {
					t.Fatal("stale authorization after lock wait", err, want)
				}
			}
			if mode != "actor" && teamMemberState(t, l, team.ID, member.PrincipalID) != "revoked" {
				t.Fatal("revocation lost")
			}
		})
	}
}

func TestTeamsConcurrentIdempotencyAndPrincipalNamespaces(t *testing.T) {
	l, owner := teamLab(t)
	addMember(t, l, owner, "other", authorization.OrgAdmin)
	other := teamPrincipal(t, l, "other")
	type result struct {
		r   APIReceipt
		err error
	}
	done := make(chan result, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			r, err := l.a.CreateTeam(t.Context(), owner, "same-key", CreateTeamInput{"same-name"})
			done <- result{r, err}
		}()
	}
	close(start)
	a, b := <-done, <-done
	if a.err != nil || b.err != nil || a.r.Replayed == b.r.Replayed || string(a.r.Body) != string(b.r.Body) {
		t.Fatal("concurrent creation", a.err, b.err)
	}
	if _, err := l.a.CreateTeam(t.Context(), other, "same-key", CreateTeamInput{"same-name"}); err != nil {
		t.Fatal(err)
	}
	if count(t, l.s, "teams") != 2 || count(t, l.s, "tenant_team_audit") != 2 {
		t.Fatal("namespace collapse")
	}
	if _, err := l.a.CreateTeam(t.Context(), owner, "same-key", CreateTeamInput{"different"}); !errors.Is(err, ErrConflict) {
		t.Fatal("body mismatch", err)
	}
	var team Team
	if err := json.Unmarshal(a.r.Body, &team); err != nil {
		t.Fatal(err)
	}
	start = make(chan struct{})
	for range 2 {
		go func() {
			<-start
			r, err := l.a.AddTeamMember(t.Context(), owner, team.ID, "same-key", AddTeamMemberInput{other.ID})
			done <- result{r, err}
		}()
	}
	close(start)
	a, b = <-done, <-done
	if a.err != nil || b.err != nil || a.r.Replayed == b.r.Replayed || string(a.r.Body) != string(b.r.Body) || count(t, l.s, "team_memberships") != 1 || count(t, l.s, "tenant_team_audit") != 3 {
		t.Fatal("concurrent membership", a.err, b.err)
	}
}

func TestTeamsMigrationPreservesExistingTeamsAndReceipts(t *testing.T) {
	l, owner := teamLab(t)
	team := createTeam(t, l, owner, "existing")
	if _, err := l.a.AddTeamMember(t.Context(), owner, team.ID, "join", AddTeamMemberInput{owner.ID}); err != nil {
		t.Fatal(err)
	}
	// Test-only pre-v6 schema: later migration tables/receipts must also be
	// removed so this fixture never invents a hole in the installed ledger.
	revertTenantAgents(t, l.s)
	if _, err := l.s.pool.Exec(t.Context(), `DROP TABLE placement_control_contracts,tenant_team_audit; ALTER TABLE api_tokens DROP COLUMN issued_by_token_id; DELETE FROM schema_migrations WHERE version>=6`); err != nil {
		t.Fatal(err)
	}
	if err := l.s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := l.a.CreateTeam(t.Context(), owner, "existing", CreateTeamInput{"existing"})
	if err != nil || !r.Replayed || count(t, l.s, "teams") != 1 || teamMemberState(t, l, team.ID, owner.ID) != "active" {
		t.Fatal("migration changed existing state", err)
	}
}
