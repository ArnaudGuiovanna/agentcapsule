package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func organizationLab(t *testing.T) (*Store, *Accounts, Principal, string, Principal) {
	t.Helper()
	s, a, legacy := accountLab(t)
	secret := "acpp_" + tokenSecret()[4:]
	if err := s.BootstrapPlatformToken(t.Context(), "platform-test", secret, time.Hour); err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(t.Context(), secret)
	if err != nil || p.Kind != "platform" {
		t.Fatal("platform authentication", err)
	}
	return s, a, p, secret, legacy
}

func organizationInput() CreateOrganizationInput {
	return CreateOrganizationInput{Name: "Engineering", InitialOwner: InitialOrganizationOwner{
		Issuer: "https://issuer.example", Subject: "initial-owner", DisplayName: "Initial Owner"}}
}

func createTestOrganization(t *testing.T, a *Accounts, p Principal, key string) CreateOrganizationResponse {
	t.Helper()
	r, err := a.CreateOrganization(t.Context(), p, key, organizationInput())
	if err != nil || r.Status != 201 {
		t.Fatal("create organization", err)
	}
	var o CreateOrganizationResponse
	if err = json.Unmarshal(r.Body, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestPlatformBootstrapSeparateStableAndHashed(t *testing.T) {
	s, _, p, secret, legacy := organizationLab(t)
	var hash []byte
	var before, after time.Time
	if err := s.pool.QueryRow(t.Context(), "SELECT token_hash,expires_at FROM platform_credentials WHERE id=$1", p.TokenID).Scan(&hash, &before); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(secret))
	if !bytes.Equal(hash, want[:]) || count(t, s, "api_tokens") != 1 {
		t.Fatal("credential crossed legacy domain or was not hashed")
	}
	if err := s.BootstrapPlatformToken(t.Context(), p.ID, secret, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(t.Context(), "SELECT expires_at FROM platform_credentials WHERE id=$1", p.TokenID).Scan(&after); err != nil || !before.Equal(after) {
		t.Fatal("bootstrap retry extended authority", err)
	}
	if err := s.BootstrapPlatformToken(t.Context(), "different", secret, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("bootstrap rebound account", err)
	}
	for _, bad := range []string{"acpp_" + strings.Repeat("!", 43), "acpp_" + strings.Repeat("A", 42), "acp_" + secret[5:]} {
		if err := s.BootstrapPlatformToken(t.Context(), p.ID, bad, time.Hour); !errors.Is(err, ErrInput) {
			t.Fatal("invalid platform token accepted", err)
		}
	}
	if _, err := s.pool.Exec(t.Context(), "UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE id=$1", p.TokenID); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapPlatformToken(t.Context(), p.ID, secret, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("bootstrap revived revoked token", err)
	}
	if _, err := s.Authenticate(t.Context(), secret); !errors.Is(err, ErrAuthentication) {
		t.Fatal("revoked token authenticated", err)
	}
	if legacy.Kind != "service" || count(t, s, "platform_credentials") != 1 {
		t.Fatal("legacy identity elevated or duplicate bootstrap")
	}
}

func TestOrganizationCreationConcurrentIdempotenceAndIdentity(t *testing.T) {
	s, a, p, _, legacy := organizationLab(t)
	var wg sync.WaitGroup
	results := make(chan APIReceipt, 16)
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			r, err := a.CreateOrganization(t.Context(), p, "shared", organizationInput())
			if err != nil {
				errs <- err
			} else {
				results <- r
			}
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrInProgress) {
			t.Fatal(err)
		}
	}
	var first []byte
	for r := range results {
		if first == nil {
			first = r.Body
		}
		if r.Status != 201 || !bytes.Equal(first, r.Body) {
			t.Fatal("concurrent receipt changed")
		}
	}
	if first == nil {
		t.Fatal("no creation completed")
	}
	r, err := a.CreateOrganization(t.Context(), p, "shared", organizationInput())
	if err != nil || !r.Replayed || !bytes.Equal(first, r.Body) {
		t.Fatal("retry changed", err)
	}
	for _, table := range []string{"organizations", "principals", "memberships", "organization_audit", "http_receipts"} {
		if count(t, s, table) != 1 {
			t.Fatal("non-atomic duplicate", table)
		}
	}
	var o CreateOrganizationResponse
	if err := json.Unmarshal(first, &o); err != nil {
		t.Fatal(err)
	}
	var correct bool
	if err := s.pool.QueryRow(t.Context(), `SELECT p.kind='user' AND p.issuer=$3 AND p.subject=$4 AND m.role='org_owner'
        FROM principals p JOIN memberships m ON m.tenant_id=p.tenant_id AND m.principal_id=p.id
        WHERE p.id=$1 AND p.tenant_id=$2`, o.OwnerPrincipalID, o.ID, organizationInput().InitialOwner.Issuer, organizationInput().InitialOwner.Subject).Scan(&correct); err != nil || !correct {
		t.Fatal("initial identity/membership missing", err)
	}
	if count(t, s, "users") != 0 || count(t, s, "api_tokens") != 1 {
		t.Fatal("registered identity gained legacy access")
	}
	changed := organizationInput()
	changed.Name = "Changed"
	if _, err := a.CreateOrganization(t.Context(), p, "shared", changed); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting replay", err)
	}
	if _, err := a.CreateOrganization(t.Context(), legacy, "forbidden", organizationInput()); !errors.Is(err, ErrForbidden) {
		t.Fatal("legacy admin elevated", err)
	}
	if _, err := a.ListUsers(t.Context(), p, "", 100); !errors.Is(err, ErrForbidden) {
		t.Fatal("platform read legacy users", err)
	}
	if _, err := a.Me(t.Context(), p); !errors.Is(err, ErrForbidden) {
		t.Fatal("platform became owner", err)
	}
	if _, err := a.ListOrganizations(t.Context(), p, "", 0); !errors.Is(err, ErrInput) {
		t.Fatal("unbounded list", err)
	}
	items, err := a.ListOrganizations(t.Context(), p, "", 1)
	if err != nil || len(items) != 1 || items[0].ID != o.ID {
		t.Fatal("organization list", err)
	}
	items, err = a.ListOrganizations(t.Context(), p, o.ID, 1)
	if err != nil || len(items) != 0 {
		t.Fatal("organization cursor", err)
	}
}

func TestOrganizationAuditFailureRollsBackCreationAndDisable(t *testing.T) {
	s, a, p, _, _ := organizationLab(t)
	_, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_org_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END $$;
        CREATE TRIGGER reject_org_audit BEFORE INSERT ON organization_audit FOR EACH ROW EXECUTE FUNCTION reject_org_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateOrganization(t.Context(), p, "atomic", organizationInput()); err == nil {
		t.Fatal("unaudited creation committed")
	}
	for _, table := range []string{"organizations", "principals", "memberships", "organization_audit", "http_receipts"} {
		if count(t, s, table) != 0 {
			t.Fatal("partial creation", table)
		}
	}
	if _, err := s.pool.Exec(t.Context(), "ALTER TABLE organization_audit DISABLE TRIGGER reject_org_audit"); err != nil {
		t.Fatal(err)
	}
	o := createTestOrganization(t, a, p, "atomic")
	if _, err := s.pool.Exec(t.Context(), "ALTER TABLE organization_audit ENABLE TRIGGER reject_org_audit"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DisableOrganization(t.Context(), p, o.ID, "disable"); err == nil {
		t.Fatal("unaudited disable committed")
	}
	got, err := a.GetOrganization(t.Context(), p, o.ID)
	if err != nil || got.Status != "active" || got.PolicyVersion != 1 || count(t, s, "http_receipts") != 1 {
		t.Fatal("partial disable", err)
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_org_audit ON organization_audit"); err != nil {
		t.Fatal(err)
	}
	r, err := a.DisableOrganization(t.Context(), p, o.ID, "disable")
	if err != nil || r.Status != 200 {
		t.Fatal(err)
	}
	replay, err := a.DisableOrganization(t.Context(), p, o.ID, "disable")
	if err != nil || !replay.Replayed || !bytes.Equal(r.Body, replay.Body) {
		t.Fatal("disable replay", err)
	}
	if count(t, s, "organization_audit") != 2 {
		t.Fatal("replay duplicated audit")
	}
	if _, err = a.DisableOrganization(t.Context(), p, o.ID, "another-disable"); err != nil {
		t.Fatal(err)
	}
	got, err = a.GetOrganization(t.Context(), p, o.ID)
	if err != nil || got.Status != "disabled" || got.PolicyVersion != 2 {
		t.Fatal("disable not stable", err)
	}
	var changed bool
	if err := s.pool.QueryRow(t.Context(), "SELECT changed FROM organization_audit WHERE action='organization.disabled' ORDER BY created_at DESC LIMIT 1").Scan(&changed); err != nil || changed {
		t.Fatal("repeated disable audit", err)
	}
	if count(t, s, "principals") != 1 || count(t, s, "memberships") != 1 {
		t.Fatal("disable deleted identities")
	}
}

func TestPlatformAuthorizationRecheckedBeforeReplay(t *testing.T) {
	for _, mode := range []string{"revoked", "expired", "hash-changed", "scope-removed"} {
		t.Run(mode, func(t *testing.T) {
			s, a, p, secret, _ := organizationLab(t)
			o := createTestOrganization(t, a, p, "create")
			query := map[string]string{
				"revoked":       "UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE id=$1",
				"expired":       "UPDATE platform_credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
				"hash-changed":  "UPDATE platform_credentials SET token_hash=decode(repeat('00',32),'hex') WHERE id=$1",
				"scope-removed": "UPDATE platform_credentials SET scopes='{}' WHERE id=$1",
			}[mode]
			if _, err := s.pool.Exec(t.Context(), query, p.TokenID); err != nil {
				t.Fatal(err)
			}
			want := ErrAuthentication
			if mode == "scope-removed" {
				want = ErrForbidden
			}
			r, err := a.CreateOrganization(t.Context(), p, "create", organizationInput())
			if !errors.Is(err, want) || len(r.Body) != 0 {
				t.Fatal("stale authority replayed receipt", err)
			}
			if _, err = a.GetOrganization(t.Context(), p, o.ID); !errors.Is(err, want) {
				t.Fatal("stale authority read", err)
			}
			if _, err = a.ListOrganizations(t.Context(), p, "", 100); !errors.Is(err, want) {
				t.Fatal("stale authority listed", err)
			}
			if _, err = a.DisableOrganization(t.Context(), p, o.ID, "disable"); !errors.Is(err, want) {
				t.Fatal("stale authority disabled", err)
			}
			if mode != "scope-removed" {
				if _, err = s.Authenticate(t.Context(), secret); !errors.Is(err, ErrAuthentication) {
					t.Fatal("stale secret authenticated", err)
				}
			}
			if count(t, s, "organization_audit") != 1 || count(t, s, "http_receipts") != 1 {
				t.Fatal("refused operation wrote data")
			}
		})
	}
}

func TestPlatformAuthorizationHoldsRevocationUntilCommit(t *testing.T) {
	s, _, p, _, _ := organizationLab(t)
	tx, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if err = authorizePlatform(t.Context(), tx, p); err != nil {
		t.Fatal(err)
	}
	var blocker uint32
	if err = tx.QueryRow(t.Context(), "SELECT pg_backend_pid()").Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	c, err := s.pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	pid := c.Conn().PgConn().PID()
	done := make(chan error, 1)
	go func() {
		_, err := c.Exec(t.Context(), "UPDATE platform_credentials SET revoked_at=clock_timestamp() WHERE id=$1", p.TokenID)
		done <- err
	}()
	finished := false
	defer func() {
		rollback(tx)
		if !finished {
			<-done
		}
	}()
	blocked := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err = s.pool.QueryRow(t.Context(), "SELECT $1=ANY(pg_blocking_pids($2))", blocker, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("revocation did not wait on transaction authority")
	}
	if err = commit(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	finished = true
	if err != nil {
		t.Fatal("revocation after commit", err)
	}
	tx, err = s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if err := authorizePlatform(t.Context(), tx, p); !errors.Is(err, ErrAuthentication) {
		t.Fatal("later transaction admitted revoked principal", err)
	}
}

func TestOrganizationRegisteredIdentityProfile(t *testing.T) {
	s, a, p, _, _ := organizationLab(t)
	for _, value := range []string{"", " issuer", "issuer ", "issuer\n", strings.Repeat("é", 513)} {
		for _, field := range []string{"issuer", "subject"} {
			in := organizationInput()
			if field == "issuer" {
				in.InitialOwner.Issuer = value
			} else {
				in.InitialOwner.Subject = value
			}
			if _, err := a.CreateOrganization(t.Context(), p, "invalid", in); !errors.Is(err, ErrInput) {
				t.Fatal("registered identity incompatible with authentication profile", field, err)
			}
		}
	}
	if count(t, s, "organizations") != 0 {
		t.Fatal("invalid identity created organization")
	}
}

func TestPlatformMigrationPreservesLegacyReceiptAndHistory(t *testing.T) {
	s, a, legacy := accountLab(t)
	in := CreateUserInput{DisplayName: "Legacy receipt owner"}
	before, err := a.CreateUser(t.Context(), legacy, "legacy-receipt", in)
	if err != nil {
		t.Fatal(err)
	}
	var oldCipher []byte
	var applied time.Time
	if err := s.pool.QueryRow(t.Context(), "SELECT response_ciphertext FROM http_receipts WHERE key='legacy-receipt'").Scan(&oldCipher); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(t.Context(), "SELECT applied_at FROM schema_migrations WHERE version=2").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the exact pre-platform schema in this isolated fixture only.
	revertTenantAgents(t, s)
	if _, err := s.pool.Exec(t.Context(), `DROP TABLE placement_control_contracts,tenant_team_audit,tenant_http_receipts,tenant_member_audit,delegation_audit,delegation_admin_receipts,delegation_revocations,delegation_trusts,delegation_issuers,organization_audit,platform_credentials;
        ALTER TABLE http_receipts DROP CONSTRAINT http_receipts_actor_kind_check;
        ALTER TABLE http_receipts ADD CONSTRAINT http_receipts_actor_kind_check CHECK (actor_kind IN ('user','service'));
        ALTER TABLE api_tokens DROP COLUMN issued_by_token_id;
        DELETE FROM schema_migrations WHERE version>=3`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := a.CreateUser(t.Context(), legacy, "legacy-receipt", in)
	if err != nil || !after.Replayed || !bytes.Equal(before.Body, after.Body) {
		t.Fatal("platform migration broke legacy receipt authentication", err)
	}
	var cipher []byte
	var appliedAfter time.Time
	if err := s.pool.QueryRow(t.Context(), "SELECT response_ciphertext FROM http_receipts WHERE key='legacy-receipt'").Scan(&cipher); err != nil || !bytes.Equal(oldCipher, cipher) {
		t.Fatal("platform migration rewrote encrypted receipt", err)
	}
	if err := s.pool.QueryRow(t.Context(), "SELECT applied_at FROM schema_migrations WHERE version=2").Scan(&appliedAfter); err != nil || !applied.Equal(appliedAfter) {
		t.Fatal("platform migration rewrote installed history", err)
	}
	if count(t, s, "platform_credentials") != 0 || count(t, s, "principals") != 0 || count(t, s, "users") != 1 {
		t.Fatal("platform migration elevated or copied legacy identity")
	}
}

func TestPlatformCredentialCanBeReplacedAfterRevocationOrExpiry(t *testing.T) {
	s, _, p, old, _ := organizationLab(t)
	fresh := func() string { return "acpp_" + tokenSecret()[4:] }
	// While a credential is active, a different secret cannot be added.
	if err := s.BootstrapPlatformToken(t.Context(), "platform-test", fresh(), time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("second active platform credential accepted", err)
	}
	if err := s.RevokeOperatorCredential(t.Context(), "platform", p.TokenID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeOperatorCredential(t.Context(), "platform", p.TokenID); err != nil {
		t.Fatal("revocation is not idempotent", err)
	}
	if _, err := s.Authenticate(t.Context(), old); !errors.Is(err, ErrAuthentication) {
		t.Fatal("revoked credential still authenticates", err)
	}
	if err := s.BootstrapPlatformToken(t.Context(), "platform-test", old, time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatal("old secret was reused", err)
	}
	replacement := fresh()
	if err := s.BootstrapPlatformToken(t.Context(), "platform-test", replacement, time.Hour); err != nil {
		t.Fatal("operator locked out after revocation:", err)
	}
	if q, err := s.Authenticate(t.Context(), replacement); err != nil || q.Kind != "platform" {
		t.Fatal("replacement credential does not authenticate", err)
	}
	// An expired credential is replaceable the same way.
	if _, err := s.pool.Exec(t.Context(), "UPDATE platform_credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE revoked_at IS NULL"); err != nil {
		t.Fatal(err)
	}
	if err := s.BootstrapPlatformToken(t.Context(), "platform-test", fresh(), time.Hour); err != nil {
		t.Fatal("operator locked out after expiry:", err)
	}
	if err := s.RevokeOperatorCredential(t.Context(), "platform", "ptok_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown credential reported as revoked", err)
	}
	if err := s.RevokeOperatorCredential(t.Context(), "other", "x"); !errors.Is(err, ErrInput) {
		t.Fatal("unknown kind accepted", err)
	}
	list, err := s.ListOperatorCredentials(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]int{}
	for _, c := range list {
		if c.Kind == "platform" {
			status[c.Status]++
		}
	}
	if status["revoked"] != 1 || status["expired"] != 1 || status["active"] != 1 {
		t.Fatal("credential listing does not reflect state:", status)
	}
}
