package controlplane

import (
	"bytes"
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

func TestTenantReceiptHistoryPreventsKeyReinitialization(t *testing.T) {
	l, owner := memberLab(t)
	addMember(t, l, owner, "history", authorization.AgentUser)
	if _, err := l.s.pool.Exec(t.Context(), `DELETE FROM http_receipts; DELETE FROM api_receipt_key`); err != nil {
		t.Fatal(err)
	}
	other, err := NewAccounts(l.s, bytes.Repeat([]byte{0xff}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = other.InitializeReceiptKey(t.Context()); !errors.Is(err, ErrReceiptKey) {
		t.Fatal("tenant history rebound to different key", err)
	}
	if count(t, l.s, "api_receipt_key") != 0 {
		t.Fatal("key installed despite history")
	}
}

func memberLab(t *testing.T) (*tenantLab, Principal) {
	t.Helper()
	l := newTenantLab(t, false)
	l.trust.AllowedScopes = []string{"org:read", "member:read", "member:manage"}
	var err error
	l.v, err = delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	l.cutoff = l.change(t, "install", "members-install", "", &l.trust).MinimumIAT
	waitTenantClock(t, l.s, l.cutoff)
	return l, memberPrincipal(t, l, organizationInput().InitialOwner.Subject)
}
func memberPrincipal(t *testing.T, l *tenantLab, subject string) Principal {
	t.Helper()
	raw := l.sign(t, newID("jti"), l.cutoff, func(c jwt.MapClaims) { c["sub"] = subject; c["scope"] = "org:read member:read member:manage" })
	p, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func memberInput(l *tenantLab, subject string, role authorization.Role) CreateMemberInput {
	return CreateMemberInput{Issuer: l.trust.Issuer, Subject: subject, DisplayName: subject, Role: role}
}
func addMember(t *testing.T, l *tenantLab, actor Principal, subject string, role authorization.Role) Member {
	t.Helper()
	r, err := l.a.CreateMember(t.Context(), actor, "add-"+subject, memberInput(l, subject, role))
	var member Member
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &member) != nil {
		t.Fatal("create member", err, r.Status)
	}
	return member
}

func TestMembersRecheckActorAndTargetBeforeReceipt(t *testing.T) {
	l, owner := memberLab(t)
	admin := addMember(t, l, owner, "admin", authorization.OrgAdmin)
	a := memberPrincipal(t, l, "admin")
	created := addMember(t, l, a, "managed", authorization.AgentUser)
	if _, err := l.a.ChangeMemberRole(t.Context(), owner, created.PrincipalID, "promote", ChangeMemberRoleInput{authorization.OrgAdmin}); err != nil {
		t.Fatal(err)
	}
	// Original creation is now a protected target. The stored receipt must not
	// bypass today's target role, even though its original input is unchanged.
	if _, err := l.a.CreateMember(t.Context(), a, "add-managed", memberInput(l, "managed", authorization.AgentUser)); !errors.Is(err, ErrForbidden) {
		t.Fatal("target rights bypassed on replay", err)
	}
	if _, err := l.a.ChangeMemberRole(t.Context(), owner, admin.PrincipalID, "demote", ChangeMemberRoleInput{authorization.AgentUser}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.a.CreateMember(t.Context(), a, "fresh", memberInput(l, "new", authorization.AgentUser)); !errors.Is(err, ErrForbidden) {
		t.Fatal("stale administrator admitted", err)
	}
	if _, err := l.a.CreateMember(t.Context(), a, "add-managed", memberInput(l, "managed", authorization.AgentUser)); !errors.Is(err, ErrForbidden) {
		t.Fatal("stale actor replay", err)
	}
}

func TestMembersConcurrentLastOwnerChanges(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := "demotion"
		if revoke {
			name = "revocation"
		}
		t.Run(name, func(t *testing.T) {
			l, owner := memberLab(t)
			other := addMember(t, l, owner, "second-owner", authorization.OrgOwner)
			second := memberPrincipal(t, l, "second-owner")
			start := make(chan struct{})
			done := make(chan error, 2)
			for _, actor := range []Principal{owner, second} {
				go func(p Principal) {
					<-start
					var err error
					if revoke {
						_, err = l.a.RevokeMember(t.Context(), p, p.ID, "self-revoke")
					} else {
						_, err = l.a.ChangeMemberRole(t.Context(), p, p.ID, "self-demote", ChangeMemberRoleInput{authorization.AgentUser})
					}
					done <- err
				}(actor)
			}
			close(start)
			errs := []error{<-done, <-done}
			passed, refused := 0, 0
			for _, err := range errs {
				if err == nil {
					passed++
				} else if errors.Is(err, ErrTransition) {
					refused++
				} else {
					t.Fatal("unexpected concurrent error", err)
				}
			}
			var owners int
			if err := l.s.pool.QueryRow(t.Context(), `SELECT count(*) FROM memberships WHERE tenant_id=$1 AND status='active' AND role='org_owner'`, l.org.ID).Scan(&owners); err != nil {
				t.Fatal(err)
			}
			if passed != 1 || refused != 1 || owners != 1 {
				t.Fatal("lost last owner", passed, refused, owners, other.PrincipalID)
			}
		})
	}
}

func TestMembersRevocationWaitsForAdmissionAndRefusesStaleReplay(t *testing.T) {
	l, owner := memberLab(t)
	victim := addMember(t, l, owner, "victim", authorization.OrgAdmin)
	v := memberPrincipal(t, l, "victim")
	addMember(t, l, v, "durable-created", authorization.AgentUser)
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO teams(id,tenant_id,name) VALUES('team',$1,'team');`, l.org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO team_memberships(tenant_id,team_id,principal_id) VALUES($1,'team',$2)`, l.org.ID, v.ID); err != nil {
		t.Fatal(err)
	}
	agents := count(t, l.s, "agents")
	tx, err := l.s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = authorizeTenant(t.Context(), tx, v, "member:read"); err != nil {
		t.Fatal(err)
	}
	var pid uint32
	if err = tx.QueryRow(t.Context(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := l.a.RevokeMember(ctx, owner, victim.PrincipalID, "revoke"); done <- e }()
	finished := false
	defer func() {
		rollback(tx)
		cancel()
		if !finished {
			<-done
		}
	}()
	waitMemberBlock(t, l.s.pool, pid, 1)
	if err = commit(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	finished = true
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.CreateMember(t.Context(), v, "add-durable-created", memberInput(l, "durable-created", authorization.AgentUser)); !errors.Is(err, ErrAuthentication) {
		t.Fatal("replay after confirmed revocation", err)
	}
	if _, err = l.a.CreateMember(t.Context(), v, "new", memberInput(l, "after-revoke", authorization.AgentUser)); !errors.Is(err, ErrAuthentication) {
		t.Fatal("consumption after confirmed revocation", err)
	}
	if _, err = l.a.ListMembers(t.Context(), v, "", 100); !errors.Is(err, ErrAuthentication) {
		t.Fatal("read after confirmed revocation", err)
	}
	var status string
	if err = l.s.pool.QueryRow(t.Context(), `SELECT status FROM team_memberships WHERE tenant_id=$1 AND principal_id=$2`, l.org.ID, v.ID).Scan(&status); err != nil || status != "revoked" {
		t.Fatal("team membership retained", err, status)
	}
	if count(t, l.s, "principals") != 3 || count(t, l.s, "agents") != agents {
		t.Fatal("offboarding removed durable resources")
	}
	if _, err = l.a.CreateMember(t.Context(), owner, "resurrect", memberInput(l, "victim", authorization.OrgAdmin)); !errors.Is(err, ErrTransition) {
		t.Fatal("duplicate resurrected revoked identity", err)
	}
	if _, err = l.a.ChangeMemberRole(t.Context(), owner, v.ID, "resurrect-role", ChangeMemberRoleInput{authorization.AgentUser}); !errors.Is(err, ErrTransition) {
		t.Fatal("role change resurrected identity", err)
	}
}

func waitMemberBlock(t *testing.T, observer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, pid uint32, minimum int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blocked int
		// A second row-lock waiter can wait on the first waiter’s tuple lock,
		// rather than directly on the revocation's transaction lock. Follow the
		// blocking chain so both callers are observed before releasing the gate.
		if err := observer.QueryRow(ctx, `WITH RECURSIVE blocked(pid) AS (
            SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
            UNION
            SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid))
        ) SELECT count(*) FROM blocked`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked >= minimum {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("did not observe %d transaction(s) waiting on blocker %d", minimum, pid)
}

func TestMembersArrivedMutationAndReplayRecheckAfterWaitingForRevocation(t *testing.T) {
	l, owner := memberLab(t)
	member := addMember(t, l, owner, "revoked-admin", authorization.OrgAdmin)
	actor := memberPrincipal(t, l, "revoked-admin")
	addMember(t, l, actor, "before-revocation", authorization.AgentUser)
	// Four connections are sufficient for the gate, revocation and two callers.
	// Exercise the default on small CI hosts even when this machine has more CPUs.
	poolConfig := l.s.pool.Config()
	poolConfig.MaxConns = 4
	poolConfig.MinConns = 0
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	l.s.pool.Close()
	l.s.pool = pool
	// Observation must not compete with the four transactions being observed.
	observer, err := pgx.ConnectConfig(t.Context(), poolConfig.ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = observer.Close(ctx)
	}()
	gate, err := l.s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(gate)
	const gateKey int64 = 98765432101235
	if _, err = gate.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, gateKey); err != nil {
		t.Fatal(err)
	}
	var gatePID uint32
	if err = gate.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&gatePID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.pool.Exec(t.Context(), `CREATE FUNCTION wait_member_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.action='member.revoked' THEN PERFORM pg_advisory_xact_lock(98765432101235::bigint); END IF; RETURN NEW; END $$;
CREATE TRIGGER wait_member_audit BEFORE INSERT ON tenant_member_audit FOR EACH ROW EXECUTE FUNCTION wait_member_audit()`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	revoked := make(chan error, 1)
	go func() { _, err := l.a.RevokeMember(ctx, owner, member.PrincipalID, "gate-revoke"); revoked <- err }()
	revocationFinished := false
	defer func() {
		rollback(gate)
		cancel()
		if !revocationFinished {
			<-revoked
		}
	}()
	waitMemberBlock(t, observer, gatePID, 1)
	var revokePID uint32
	if err = observer.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, gatePID).Scan(&revokePID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for _, subject := range []string{"before-revocation", "new-after-revocation"} {
		go func(subject string) {
			_, err := l.a.CreateMember(ctx, actor, "add-"+subject, memberInput(l, subject, authorization.AgentUser))
			done <- err
		}(subject)
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
	waitMemberBlock(t, observer, revokePID, 2)
	if err = commit(t.Context(), gate); err != nil {
		t.Fatal(err)
	}
	err = <-revoked
	revocationFinished = true
	if err != nil {
		t.Fatal(err)
	}
	for consumed < 2 {
		err = <-done
		consumed++
		if !errors.Is(err, ErrAuthentication) {
			t.Fatal("stale membership used after org lock wait", err)
		}
	}
	if count(t, l.s, "principals") != 3 || count(t, l.s, "tenant_http_receipts") != 3 {
		t.Fatal("refused request committed work or receipt")
	}
}

func TestMembersAuditFailureRollsBackMutationAndReceipt(t *testing.T) {
	l, owner := memberLab(t)
	victim := addMember(t, l, owner, "victim", authorization.AgentUser)
	beforeReceipts, beforeAudit := count(t, l.s, "tenant_http_receipts"), count(t, l.s, "tenant_member_audit")
	var beforeVersion int64
	if err := l.s.pool.QueryRow(t.Context(), `SELECT policy_version FROM organizations WHERE id=$1`, l.org.ID).Scan(&beforeVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(t.Context(), `CREATE FUNCTION fail_member_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$;
CREATE TRIGGER fail_member_audit BEFORE INSERT ON tenant_member_audit FOR EACH ROW EXECUTE FUNCTION fail_member_audit()`); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"create", "role", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			var err error
			switch operation {
			case "create":
				_, err = l.a.CreateMember(t.Context(), owner, "failing-create", memberInput(l, "must-rollback", authorization.AgentUser))
			case "role":
				_, err = l.a.ChangeMemberRole(t.Context(), owner, victim.PrincipalID, "failing-role", ChangeMemberRoleInput{authorization.OrgAdmin})
			case "revoke":
				_, err = l.a.RevokeMember(t.Context(), owner, victim.PrincipalID, "failing-revoke")
			}
			if err == nil {
				t.Fatal("audit failure acknowledged")
			}
			if count(t, l.s, "principals") != 2 || count(t, l.s, "tenant_http_receipts") != beforeReceipts || count(t, l.s, "tenant_member_audit") != beforeAudit {
				t.Fatal("partial commit")
			}
			var status, role string
			var version int64
			if err = l.s.pool.QueryRow(t.Context(), `SELECT m.status,m.role,o.policy_version FROM memberships m JOIN organizations o ON o.id=m.tenant_id WHERE m.tenant_id=$1 AND m.principal_id=$2`, l.org.ID, victim.PrincipalID).Scan(&status, &role, &version); err != nil {
				t.Fatal(err)
			}
			if status != "active" || role != "agent_user" || version != beforeVersion {
				t.Fatal("audit failure leaked mutation", status, role, version)
			}
		})
	}
}

func TestTenantReceiptsBindNamespaceAndRejectCiphertextSubstitution(t *testing.T) {
	l, owner := memberLab(t)
	other := addMember(t, l, owner, "other-owner", authorization.OrgOwner)
	p := memberPrincipal(t, l, "other-owner")
	first, err := l.a.CreateMember(t.Context(), owner, "shared", memberInput(l, "first", authorization.AgentUser))
	if err != nil {
		t.Fatal(err)
	}
	second, err := l.a.CreateMember(t.Context(), p, "shared", memberInput(l, "second", authorization.AgentUser))
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Body) == string(second.Body) {
		t.Fatal("principals shared receipt")
	}
	if _, err = l.s.pool.Exec(t.Context(), `UPDATE tenant_http_receipts a SET response_ciphertext=b.response_ciphertext,request_hash=b.request_hash,response_status=b.response_status FROM tenant_http_receipts b WHERE a.tenant_id=$1 AND a.principal_id=$2 AND a.key='shared' AND b.tenant_id=$1 AND b.principal_id=$3 AND b.key='shared'`, l.org.ID, owner.ID, other.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.a.CreateMember(t.Context(), owner, "shared", memberInput(l, "second", authorization.AgentUser)); err == nil || err.Error() != "tenant receipt cannot be decrypted" {
		t.Fatal("ciphertext copied between actors decrypted")
	}
	if count(t, l.s, "principals") != 4 {
		t.Fatal("receipt authentication failure changed state")
	}
}

func TestTenantReceiptsAuthenticateRequestAndResponseMetadata(t *testing.T) {
	l, owner := memberLab(t)
	for _, field := range []string{"request_hash", "response_status"} {
		t.Run(field, func(t *testing.T) {
			in := memberInput(l, "integrity-"+field, authorization.AgentUser)
			if _, err := l.a.CreateMember(t.Context(), owner, field, in); err != nil {
				t.Fatal(err)
			}
			if field == "request_hash" {
				// Match the forged stored hash with a new request, to reach AEAD
				// verification rather than stopping at the mismatch check.
				in.DisplayName = "changed request"
				hash, err := requestHash(in)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = l.s.pool.Exec(t.Context(), `UPDATE tenant_http_receipts SET request_hash=$4 WHERE tenant_id=$1 AND principal_id=$2 AND key=$3`, l.org.ID, owner.ID, field, hash[:]); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := l.s.pool.Exec(t.Context(), `UPDATE tenant_http_receipts SET response_status=202 WHERE tenant_id=$1 AND principal_id=$2 AND key=$3`, l.org.ID, owner.ID, field); err != nil {
					t.Fatal(err)
				}
			}
			before := count(t, l.s, "tenant_member_audit")
			if _, err := l.a.CreateMember(t.Context(), owner, field, in); err == nil || err.Error() != "tenant receipt cannot be decrypted" {
				t.Fatal("metadata not authenticated by AEAD", err)
			}
			if count(t, l.s, "tenant_member_audit") != before {
				t.Fatal("corrupt receipt caused mutation")
			}
		})
	}
}

func TestTenantReceiptsRejectTransplantAcrossKeyOperationAndTenant(t *testing.T) {
	l, owner := memberLab(t)
	in := memberInput(l, "source", authorization.AgentUser)
	r, err := l.a.CreateMember(t.Context(), owner, "source", in)
	if err != nil {
		t.Fatal(err)
	}
	var member Member
	if err = json.Unmarshal(r.Body, &member); err != nil {
		t.Fatal(err)
	}
	before := count(t, l.s, "tenant_member_audit")
	copyReceipt := func(tenant, principal, operation, key string, hash []byte) {
		t.Helper()
		if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO tenant_http_receipts(tenant_id,principal_id,operation,key,request_hash,response_status,response_ciphertext,aad_version)
SELECT $1,$2,$3,$4,$5,response_status,response_ciphertext,aad_version FROM tenant_http_receipts WHERE tenant_id=$6 AND principal_id=$7 AND operation='member.create' AND key='source'`, tenant, principal, operation, key, hash, l.org.ID, owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := requestHash(in)
	if err != nil {
		t.Fatal(err)
	}
	copyReceipt(l.org.ID, owner.ID, "member.create", "different-key", hash[:])
	if _, err = l.a.CreateMember(t.Context(), owner, "different-key", in); err == nil || err.Error() != "tenant receipt cannot be decrypted" {
		t.Fatal("key transplant reached no AEAD rejection", err)
	}
	roleInput := struct {
		PrincipalID string             `json:"principal_id"`
		Role        authorization.Role `json:"role"`
	}{member.PrincipalID, authorization.Auditor}
	roleHash, err := requestHash(roleInput)
	if err != nil {
		t.Fatal(err)
	}
	copyReceipt(l.org.ID, owner.ID, "member.change_role", "source", roleHash[:])
	if _, err = l.a.ChangeMemberRole(t.Context(), owner, member.PrincipalID, "source", ChangeMemberRoleInput{authorization.Auditor}); err == nil || err.Error() != "tenant receipt cannot be decrypted" {
		t.Fatal("operation transplant reached no AEAD rejection", err)
	}
	// Probe the receipt codec with identical request metadata across operation
	// types, isolating operation binding from the independently bound input hash.
	copyReceipt(l.org.ID, owner.ID, "member.revoke", "source", hash[:])
	tx, err := l.s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = authorizeMemberMutation(t.Context(), tx, owner); err != nil {
		t.Fatal(err)
	}
	_, err = l.a.withTenantReceipt(t.Context(), tx, owner, "member.revoke", "source", in, func() (int, any, error) { t.Error("copied receipt not found"); return 0, nil, ErrInput })
	if err == nil || err.Error() != "tenant receipt cannot be decrypted" {
		t.Fatal("operation omitted from AAD", err)
	}
	rollback(tx)
	second := createTestOrganization(t, l.a, l.platform, "second-tenant")
	secondTrust := l.trust
	secondTrust.TenantID = second.ID
	secondTrust.Audience = "second"
	activated, err := l.s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: "second-trust", Actor: "test-operator", Action: "install", TenantID: second.ID, Issuer: secondTrust.Issuer, Audience: secondTrust.Audience, Trust: &secondTrust})
	if err != nil {
		t.Fatal(err)
	}
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust, secondTrust}})
	if err != nil {
		t.Fatal(err)
	}
	waitTenantClock(t, l.s, activated.MinimumIAT)
	p, err := l.s.AuthenticateDelegation(t.Context(), v, l.sign(t, "second", activated.MinimumIAT, func(c jwt.MapClaims) { c["aud"] = "second"; c["scope"] = "member:manage" }))
	if err != nil {
		t.Fatal(err)
	}
	copyReceipt(second.ID, p.ID, "member.create", "source", hash[:])
	if _, err = l.a.CreateMember(t.Context(), p, "source", in); err == nil || err.Error() != "tenant receipt cannot be decrypted" {
		t.Fatal("tenant transplant reached no AEAD rejection", err)
	}
	if count(t, l.s, "tenant_member_audit") != before || count(t, l.s, "principals") != 3 {
		t.Fatal("transplant caused mutation")
	}
}

func TestMembersConcurrentIdenticalCreateAndPrincipalNamespaces(t *testing.T) {
	l, owner := memberLab(t)
	addMember(t, l, owner, "other-owner", authorization.OrgOwner)
	other := memberPrincipal(t, l, "other-owner")
	type result struct {
		receipt APIReceipt
		err     error
	}
	start := make(chan struct{})
	done := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			r, err := l.a.CreateMember(t.Context(), owner, "concurrent", memberInput(l, "single-member", authorization.AgentUser))
			done <- result{r, err}
		}()
	}
	close(start)
	a, b := <-done, <-done
	if a.err != nil || b.err != nil || a.receipt.Replayed == b.receipt.Replayed || string(a.receipt.Body) != string(b.receipt.Body) {
		t.Fatal("concurrent receipt", a.err, b.err, a.receipt.Replayed, b.receipt.Replayed)
	}
	if _, err := l.a.CreateMember(t.Context(), other, "concurrent", memberInput(l, "independent-member", authorization.AgentUser)); err != nil {
		t.Fatal("other principal reused key", err)
	}
	if count(t, l.s, "principals") != 4 || count(t, l.s, "tenant_member_audit") != 3 || count(t, l.s, "tenant_http_receipts") != 3 {
		t.Fatal("duplicate or missing effect")
	}
}

// A caller whose token lacks the required scope must be refused before it
// queues for the tenant-wide exclusive lock, so a read-only member cannot stall
// administrative writes by repeatedly calling a mutation route.
func TestMemberMutationWithoutScopeIsRefusedBeforeTenantLock(t *testing.T) {
	l, _ := memberLab(t)
	raw := l.sign(t, newID("jti"), l.cutoff, func(c jwt.MapClaims) {
		c["sub"] = organizationInput().InitialOwner.Subject
		c["scope"] = "org:read member:read"
	})
	reader, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := l.s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(holder)
	var id string
	if err = holder.QueryRow(t.Context(), "SELECT id FROM organizations WHERE id=$1 FOR SHARE", l.org.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err = l.a.CreateMember(ctx, reader, "no-scope", memberInput(l, "someone-new", authorization.AgentUser))
	if !errors.Is(err, ErrForbidden) {
		t.Fatal("expected ErrForbidden without waiting for the tenant lock, got", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("refusal waited for the tenant lock:", time.Since(started))
	}
}
