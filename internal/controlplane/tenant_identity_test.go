package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/golang-jwt/jwt/v5"
)

type tenantLab struct {
	s        *Store
	a        *Accounts
	platform Principal
	org      CreateOrganizationResponse
	trust    delegatedidentity.Trust
	key      ed25519.PrivateKey
	v        *delegatedidentity.Verifier
	cutoff   time.Time
	legacy   Principal
}

func newTenantLab(t *testing.T, install bool) *tenantLab {
	t.Helper()
	s, a, platform, _, legacy := organizationLab(t)
	l := &tenantLab{s: s, a: a, platform: platform, legacy: legacy, org: createTestOrganization(t, a, platform, "organization")}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l.key = key
	l.trust = delegatedidentity.Trust{TenantID: l.org.ID, Issuer: organizationInput().InitialOwner.Issuer, Audience: "capsule", Keys: map[string]ed25519.PublicKey{"key-1": pub}, AllowedScopes: []string{"org:read"}, MaxTTL: 5 * time.Minute}
	l.v, err = delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	if install {
		r := l.change(t, "install", "install", "", &l.trust)
		l.cutoff = r.MinimumIAT
		waitTenantClock(t, s, l.cutoff)
	}
	return l
}

func (l *tenantLab) change(t *testing.T, action, op, token string, trust *delegatedidentity.Trust) DelegationChangeResult {
	t.Helper()
	audience := l.trust.Audience
	if action == "revoke-token" {
		audience = ""
	}
	r, err := l.s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: op, Actor: "test-operator", Action: action, TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: audience, TokenID: token, Trust: trust})
	if err != nil {
		t.Fatal("authority change", action, err)
	}
	return r
}

func waitTenantClock(t *testing.T, s *Store, at time.Time) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var reached bool
		if err := s.pool.QueryRow(t.Context(), "SELECT clock_timestamp()>=$1::timestamptz", at).Scan(&reached); err != nil {
			t.Fatal(err)
		}
		if reached {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("database clock did not reach activation cutoff")
}

func (l *tenantLab) sign(t *testing.T, id string, at time.Time, edit func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": l.trust.Issuer, "aud": l.trust.Audience, "sub": organizationInput().InitialOwner.Subject, "jti": id, "iat": at.Unix(), "exp": at.Add(5 * time.Minute).Unix(), "scope": "org:read", "role": "platform", "trust_generation": int64(1)}
	if edit != nil {
		edit(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "key-1"
	raw, err := token.SignedString(l.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTenantIdentityNeedsExplicitTrustAndExistingIdentity(t *testing.T) {
	l := newTenantLab(t, false)
	old := l.sign(t, "before-install", time.Now().UTC().Truncate(time.Second), nil)
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, old); !errors.Is(err, ErrAuthentication) {
		t.Fatal("verifier auto-installed trust", err)
	}
	if count(t, l.s, "delegation_issuers") != 0 || count(t, l.s, "delegation_trusts") != 0 {
		t.Fatal("authentication provisioned trust")
	}
	r := l.change(t, "install", "install", "", &l.trust)
	l.cutoff = r.MinimumIAT
	waitTenantClock(t, l.s, l.cutoff)
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, old); !errors.Is(err, ErrAuthentication) {
		t.Fatal("pre-install token admitted", err)
	}
	raw := l.sign(t, "current", l.cutoff, nil)
	p, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw)
	if err != nil || p.Kind != "tenant" || p.TenantID != l.org.ID || p.ID != l.org.OwnerPrincipalID {
		t.Fatal("current identity not resolved", err)
	}
	current, err := l.a.CurrentOrganization(t.Context(), p)
	if err != nil || current.Role != "org_owner" || current.Organization.ID != l.org.ID {
		t.Fatal("current organization", err)
	}
	for _, edit := range []func(jwt.MapClaims){func(c jwt.MapClaims) { c["sub"] = "unknown" }, func(c jwt.MapClaims) { c["tenant_id"] = "another-tenant" }} {
		if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, l.sign(t, "unknown", l.cutoff, edit)); !errors.Is(err, ErrAuthentication) {
			t.Fatal("foreign identity admitted", err)
		}
	}
	if count(t, l.s, "principals") != 1 || count(t, l.s, "memberships") != 1 {
		t.Fatal("unknown subject created principal")
	}
	noScope, err := l.s.AuthenticateDelegation(t.Context(), l.v, l.sign(t, "no-scope", l.cutoff, func(c jwt.MapClaims) { delete(c, "scope") }))
	if err != nil {
		t.Fatal(err)
	}
	noScope.Scopes = []string{"org:read", "platform:admin"}
	if _, err := l.a.CurrentOrganization(t.Context(), noScope); !errors.Is(err, ErrForbidden) {
		t.Fatal("mutable scopes elevated delegation", err)
	}
	if _, err := l.a.ListUsers(t.Context(), p, "", 100); !errors.Is(err, ErrForbidden) {
		t.Fatal("tenant gained service access", err)
	}
	if _, err := l.a.Me(t.Context(), p); !errors.Is(err, ErrForbidden) {
		t.Fatal("tenant became legacy owner", err)
	}
	if _, err := l.a.ListOrganizations(t.Context(), p, "", 100); !errors.Is(err, ErrForbidden) {
		t.Fatal("tenant gained platform access", err)
	}
	p.TenantID = "another-tenant"
	if _, err := l.a.CurrentOrganization(t.Context(), p); !errors.Is(err, ErrForbidden) {
		t.Fatal("principal tenant tampering", err)
	}
}

func TestTenantIdentityRechecksCurrentState(t *testing.T) {
	for _, mode := range []string{"organization", "principal", "membership", "trust", "jti", "role"} {
		t.Run(mode, func(t *testing.T) {
			l := newTenantLab(t, true)
			raw := l.sign(t, "live", l.cutoff, nil)
			p, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "organization":
				_, err = l.a.DisableOrganization(t.Context(), l.platform, l.org.ID, "disable")
			case "principal":
				_, err = l.s.pool.Exec(t.Context(), "UPDATE principals SET status='disabled' WHERE id=$1", p.ID)
			case "membership":
				_, err = l.s.pool.Exec(t.Context(), "UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2", p.TenantID, p.ID)
			case "trust":
				l.change(t, "revoke-trust", "revoke", "", nil)
			case "jti":
				l.change(t, "revoke-token", "revoke", "live", nil)
			case "role":
				_, err = l.s.pool.Exec(t.Context(), "UPDATE memberships SET role='auditor' WHERE tenant_id=$1 AND principal_id=$2", p.TenantID, p.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			current, err := l.a.CurrentOrganization(t.Context(), p)
			if mode == "role" {
				if err != nil || current.Role != "auditor" {
					t.Fatal("stale cached role", err)
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Fatal("stale principal bypassed current state", err)
			}
		})
	}
}

func TestDelegationRotationCannotResurrectRevokedToken(t *testing.T) {
	l := newTenantLab(t, true)
	old := l.sign(t, "permanent", l.cutoff, nil)
	l.change(t, "revoke-token", "token-revocation", "permanent", nil)
	r := l.change(t, "rotate", "rotation", "", &l.trust)
	if !r.MinimumIAT.After(l.cutoff) || r.MinimumIAT.Nanosecond() != 0 || r.Generation != 2 {
		t.Fatal("rotation cutoff not strict/integer/monotone")
	}
	replay := l.change(t, "rotate", "rotation", "", &l.trust)
	if !replay.Replayed || !replay.MinimumIAT.Equal(r.MinimumIAT) {
		t.Fatal("rotation retry advanced cutoff")
	}
	waitTenantClock(t, l.s, r.MinimumIAT)
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, old); !errors.Is(err, ErrAuthentication) {
		t.Fatal("old token revived", err)
	}
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, l.sign(t, "permanent", r.MinimumIAT, func(c jwt.MapClaims) { c["trust_generation"] = r.Generation })); !errors.Is(err, ErrAuthentication) {
		t.Fatal("new trust erased JTI tombstone", err)
	}
	fresh := l.sign(t, "new", r.MinimumIAT, func(c jwt.MapClaims) { c["trust_generation"] = r.Generation })
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, fresh); err != nil {
		t.Fatal("fresh token refused", err)
	}
	l.change(t, "revoke-trust", "trust-revocation", "", nil)
	_, err := l.s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: "implicit-reactivate", Actor: "test-operator", Action: "install", TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust})
	if !errors.Is(err, ErrConflict) {
		t.Fatal("install reactivated revoked trust", err)
	}
	activated := l.change(t, "rotate", "reactivate", "", &l.trust)
	waitTenantClock(t, l.s, activated.MinimumIAT)
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, fresh); !errors.Is(err, ErrAuthentication) {
		t.Fatal("same fingerprint revived old token", err)
	}
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, l.sign(t, "reactivated", activated.MinimumIAT, func(c jwt.MapClaims) { c["trust_generation"] = activated.Generation })); err != nil {
		t.Fatal("new generation refused", err)
	}
	again := l.change(t, "install", "install-again", "", &l.trust)
	if !again.MinimumIAT.Equal(activated.MinimumIAT) {
		t.Fatal("identical active install moved cutoff")
	}
	l.change(t, "rotate", "rotation", "", &l.trust)
	var actual time.Time
	if err := l.s.pool.QueryRow(t.Context(), "SELECT minimum_iat FROM delegation_trusts WHERE tenant_id=$1", l.org.ID).Scan(&actual); err != nil || !actual.Equal(activated.MinimumIAT) {
		t.Fatal("old operation reset trust", err)
	}
	if count(t, l.s, "delegation_revocations") != 1 {
		t.Fatal("rotation removed tombstone")
	}
}

func TestTenantRevocationSerializesWithExistingAdmission(t *testing.T) {
	for _, action := range []string{"revoke-token", "revoke-trust"} {
		t.Run(action, func(t *testing.T) {
			l := newTenantLab(t, true)
			p, err := l.s.AuthenticateDelegation(t.Context(), l.v, l.sign(t, "in-flight", l.cutoff, nil))
			if err != nil {
				t.Fatal(err)
			}
			tx, err := l.s.begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollback(tx)
			if _, err = authorizeTenant(t.Context(), tx, p, "org:read"); err != nil {
				t.Fatal(err)
			}
			var pid uint32
			if err = tx.QueryRow(t.Context(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
				t.Fatal(err)
			}
			change := DelegationChange{OperationID: "race-revoke", Actor: "test-operator", Action: action, TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience}
			if action == "revoke-token" {
				change.Audience = ""
				change.TokenID = "in-flight"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, e := l.s.ChangeDelegationAuthority(ctx, change); done <- e }()
			finished := false
			defer func() {
				rollback(tx)
				cancel()
				if !finished {
					<-done
				}
			}()
			blocked := false
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if err = l.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", pid).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !blocked {
				t.Fatal("revocation bypassed admission lock")
			}
			if err = commit(t.Context(), tx); err != nil {
				t.Fatal(err)
			}
			err = <-done
			finished = true
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.a.CurrentOrganization(t.Context(), p); !errors.Is(err, ErrAuthentication) {
				t.Fatal("admitted after confirmed revocation", err)
			}
		})
	}
}

func TestTenantDatabaseClockOverridesVerifierClock(t *testing.T) {
	l := newTenantLab(t, true)
	for _, mode := range []string{"future-iat", "future-nbf", "expired"} {
		t.Run(mode, func(t *testing.T) {
			at := l.cutoff
			clock := at.Add(time.Minute)
			edit := func(c jwt.MapClaims) {}
			switch mode {
			case "future-iat":
				at = at.Add(time.Minute)
			case "future-nbf":
				edit = func(c jwt.MapClaims) { c["nbf"] = at.Add(time.Minute).Unix() }
			case "expired":
				clock = at
				edit = func(c jwt.MapClaims) { c["exp"] = at.Add(time.Second).Unix() }
				waitTenantClock(t, l.s, at.Add(time.Second))
			}
			v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}, Clock: func() time.Time { return clock }})
			if err != nil {
				t.Fatal(err)
			}
			raw := l.sign(t, "clock-"+mode, at, edit)
			if _, err := v.Verify(raw); err != nil {
				t.Fatal("test did not reach DB clock boundary", err)
			}
			if _, err := l.s.AuthenticateDelegation(t.Context(), v, raw); !errors.Is(err, ErrAuthentication) {
				t.Fatal("verifier clock bypassed DB clock", err)
			}
		})
	}
}

func TestDelegationJTIIsTenantIssuerScopedAcrossAudiences(t *testing.T) {
	l := newTenantLab(t, true)
	l.change(t, "revoke-token", "revoke-jti", "shared-jti", nil)
	second := l.trust
	second.Audience = "second-client"
	otherOrg := createTestOrganization(t, l.a, l.platform, "other-org")
	third := l.trust
	third.TenantID = otherOrg.ID
	third.Audience = "other-tenant"
	otherIssuer := l.trust
	otherIssuer.Issuer = "https://other-issuer.example"
	otherIssuer.Audience = "other-issuer"
	if _, err := l.s.pool.Exec(t.Context(), `INSERT INTO principals(id,tenant_id,kind,issuer,subject,display_name)
        VALUES('other-principal',$1,'user',$2,$3,'Other identity');
        `, l.org.ID, otherIssuer.Issuer, organizationInput().InitialOwner.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := l.s.pool.Exec(t.Context(), "INSERT INTO memberships(tenant_id,principal_id,role) VALUES($1,'other-principal','agent_user')", l.org.ID); err != nil {
		t.Fatal(err)
	}
	for i, trust := range []delegatedidentity.Trust{second, third, otherIssuer} {
		op := []string{"second-audience", "other-tenant", "other-issuer"}[i]
		r, err := l.s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: op, Actor: "test-operator", Action: "install", TenantID: trust.TenantID, Issuer: trust.Issuer, Audience: trust.Audience, Trust: &trust})
		if err != nil {
			t.Fatal(err)
		}
		waitTenantClock(t, l.s, r.MinimumIAT)
		v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{trust}})
		if err != nil {
			t.Fatal(err)
		}
		raw := l.sign(t, "shared-jti", r.MinimumIAT, func(c jwt.MapClaims) { c["iss"] = trust.Issuer; c["aud"] = trust.Audience })
		p, err := l.s.AuthenticateDelegation(t.Context(), v, raw)
		if i == 0 {
			if !errors.Is(err, ErrAuthentication) {
				t.Fatal("audience bypassed issuer-wide JTI tombstone", err)
			}
		} else if err != nil || p.TenantID != trust.TenantID {
			t.Fatal("JTI revocation crossed tenant/issuer namespace", err)
		}
	}
}

func TestDelegationTrustFingerprintAndAuditAreAuthoritative(t *testing.T) {
	l := newTenantLab(t, false)
	if _, err := l.s.pool.Exec(t.Context(), `CREATE FUNCTION reject_delegation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END $$;
        CREATE TRIGGER reject_delegation_audit BEFORE INSERT ON delegation_audit FOR EACH ROW EXECUTE FUNCTION reject_delegation_audit()`); err != nil {
		t.Fatal(err)
	}
	change := DelegationChange{OperationID: "atomic-install", Actor: "test-operator", Action: "install", TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust}
	if _, err := l.s.ChangeDelegationAuthority(t.Context(), change); err == nil {
		t.Fatal("unaudited trust committed")
	}
	for _, table := range []string{"delegation_issuers", "delegation_trusts", "delegation_admin_receipts", "delegation_audit"} {
		if count(t, l.s, table) != 0 {
			t.Fatal("partial trust activation", table)
		}
	}
	if _, err := l.s.pool.Exec(t.Context(), "ALTER TABLE delegation_audit DISABLE TRIGGER reject_delegation_audit"); err != nil {
		t.Fatal(err)
	}
	r, err := l.s.ChangeDelegationAuthority(t.Context(), change)
	if err != nil {
		t.Fatal(err)
	}
	waitTenantClock(t, l.s, r.MinimumIAT)
	changed := l.trust
	changed.AllowedScopes = []string{"org:read", "agent:invoke"}
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{changed}})
	if err != nil {
		t.Fatal(err)
	}
	raw := l.sign(t, "good", r.MinimumIAT, nil)
	if _, err := l.s.AuthenticateDelegation(t.Context(), v, raw); !errors.Is(err, ErrAuthentication) {
		t.Fatal("uninstalled config fingerprint authorized", err)
	}
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw); err != nil {
		t.Fatal(err)
	}
	conflict := change
	conflict.Trust = &changed
	if _, err := l.s.ChangeDelegationAuthority(t.Context(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatal("changed operation replay accepted", err)
	}
	if _, err := l.s.pool.Exec(t.Context(), "ALTER TABLE delegation_audit ENABLE TRIGGER reject_delegation_audit"); err != nil {
		t.Fatal(err)
	}
	revoke := DelegationChange{OperationID: "atomic-revoke", Actor: "test-operator", Action: "revoke-token", TenantID: l.org.ID, Issuer: l.trust.Issuer, TokenID: "good"}
	if _, err := l.s.ChangeDelegationAuthority(t.Context(), revoke); err == nil {
		t.Fatal("unaudited revocation committed")
	}
	if count(t, l.s, "delegation_revocations") != 0 {
		t.Fatal("failed revocation left tombstone")
	}
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw); err != nil {
		t.Fatal("rolled-back revocation changed authority", err)
	}
}

func TestTenantExpiryCheckedAgainByConsumingTransaction(t *testing.T) {
	l := newTenantLab(t, true)
	raw := l.sign(t, "expires", l.cutoff, func(c jwt.MapClaims) { c["exp"] = l.cutoff.Add(2 * time.Second).Unix() })
	p, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw)
	if err != nil {
		t.Fatal(err)
	}
	waitTenantClock(t, l.s, l.cutoff.Add(2*time.Second))
	if _, err := l.a.CurrentOrganization(t.Context(), p); !errors.Is(err, ErrAuthentication) {
		t.Fatal("cached authentication survived expiry", err)
	}
}

func TestCurrentOrganizationUsesEveryCurrentActiveRole(t *testing.T) {
	l := newTenantLab(t, true)
	p, err := l.s.AuthenticateDelegation(t.Context(), l.v, l.sign(t, "roles", l.cutoff, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"org_owner", "org_admin", "agent_operator", "agent_user", "auditor"} {
		t.Run(role, func(t *testing.T) {
			if _, err := l.s.pool.Exec(t.Context(), "UPDATE memberships SET role=$3 WHERE tenant_id=$1 AND principal_id=$2", p.TenantID, p.ID, role); err != nil {
				t.Fatal(err)
			}
			current, err := l.a.CurrentOrganization(t.Context(), p)
			if err != nil || current.Role != role {
				t.Fatal("current role not used for own metadata", err)
			}
			if _, err := l.a.ListUsers(t.Context(), p, "", 100); !errors.Is(err, ErrForbidden) {
				t.Fatal("role granted legacy administration", err)
			}
			if _, err := l.a.ListOrganizations(t.Context(), p, "", 100); !errors.Is(err, ErrForbidden) {
				t.Fatal("role granted global administration", err)
			}
		})
	}
}

func TestDelegationGenerationRejectsPresignedFutureAndCachedPrincipal(t *testing.T) {
	l := newTenantLab(t, true)
	p, err := l.s.AuthenticateDelegation(t.Context(), l.v, l.sign(t, "cached", l.cutoff, nil))
	if err != nil {
		t.Fatal(err)
	}
	future := l.cutoff.Add(3 * time.Second)
	old := l.sign(t, "presigned", future, nil)
	r := l.change(t, "rotate", "epoch-rotation", "", &l.trust)
	if r.Generation != 2 {
		t.Fatal("rotation did not advance generation")
	}
	waitTenantClock(t, l.s, future)
	if identity, err := l.v.Verify(old); err != nil || identity.TrustGeneration != 1 || identity.IssuedAt.Before(r.MinimumIAT) {
		t.Fatal("test did not isolate epoch from freshness", err)
	}
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, old); !errors.Is(err, ErrAuthentication) {
		t.Fatal("old generation accepted with future issuance claim", err)
	}
	if _, err := l.a.CurrentOrganization(t.Context(), p); !errors.Is(err, ErrAuthentication) {
		t.Fatal("middleware principal survived rotation", err)
	}
	fresh := l.sign(t, "fresh", future, func(c jwt.MapClaims) { c["trust_generation"] = r.Generation })
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, fresh); err != nil {
		t.Fatal("current signed generation refused", err)
	}
}

func TestDelegationDelayedRotationUsesSignedGeneration(t *testing.T) {
	l := newTenantLab(t, true)
	gate, err := l.s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(gate)
	const gateKey int64 = 98765432101234
	if _, err = gate.Exec(t.Context(), "SELECT pg_advisory_xact_lock($1)", gateKey); err != nil {
		t.Fatal(err)
	}
	var gatePID uint32
	if err = gate.QueryRow(t.Context(), "SELECT pg_backend_pid()").Scan(&gatePID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.s.pool.Exec(t.Context(), `CREATE FUNCTION wait_rotation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='rotate' THEN PERFORM pg_advisory_xact_lock(98765432101234::bigint); END IF; RETURN NEW; END $$;
        CREATE TRIGGER wait_rotation_audit BEFORE INSERT ON delegation_audit FOR EACH ROW EXECUTE FUNCTION wait_rotation_audit()`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	type result struct {
		out DelegationChangeResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := l.s.ChangeDelegationAuthority(ctx, DelegationChange{OperationID: "delayed-rotation", Actor: "test-operator", Action: "rotate", TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust})
		done <- result{out, err}
	}()
	finished := false
	defer func() {
		rollback(gate)
		cancel()
		if !finished {
			<-done
		}
	}()
	blocked := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err = l.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", gatePID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("rotation did not reach audit boundary after UPDATE")
	}
	var observed time.Time
	if err = l.s.pool.QueryRow(t.Context(), "SELECT clock_timestamp()").Scan(&observed); err != nil {
		t.Fatal(err)
	}
	waitTenantClock(t, l.s, observed.Add(2*time.Second))
	var issued time.Time
	if err = l.s.pool.QueryRow(t.Context(), "SELECT date_trunc('second',clock_timestamp())").Scan(&issued); err != nil {
		t.Fatal(err)
	}
	// This token is physically signed before the delayed rotation commits, but
	// its iat is already beyond the cutoff computed by that uncommitted UPDATE.
	old := l.sign(t, "signed-during-rotation", issued, nil)
	if err = commit(t.Context(), gate); err != nil {
		t.Fatal(err)
	}
	r := <-done
	finished = true
	if r.err != nil {
		t.Fatal(r.err)
	}
	if issued.Before(r.out.MinimumIAT) {
		t.Fatal("test did not cross precommit cutoff")
	}
	if _, err := l.v.Verify(old); err != nil {
		t.Fatal("signature/time should remain valid", err)
	}
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, old); !errors.Is(err, ErrAuthentication) {
		t.Fatal("precommit cutoff replaced epoch comparison", err)
	}
	fresh := l.sign(t, "new-generation", issued, func(c jwt.MapClaims) { c["trust_generation"] = r.out.Generation })
	if _, err := l.s.AuthenticateDelegation(t.Context(), l.v, fresh); err != nil {
		t.Fatal("new epoch refused after delayed commit", err)
	}
}
