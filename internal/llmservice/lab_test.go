package llmservice

// The tests of the service moved here from internal/controlplane with it
// (v0.1.0 audit, finding A-02). They read the control plane's API unqualified,
// as they did there, and this file gives them the fixtures they used, built
// on that API alone: an organization in a schema of its own on the PostgreSQL
// of scripts/verify-postgres.py, its owner, its agents, providers and
// aliases. db is a pool on the same schema for what a test reads or sets
// directly.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const providerSecret = "sk-test-0123456789-abcdef" // gitleaks:allow test fixture, not a credential

const agentScopes = "org:read member:read member:manage team:read team:manage agent:read agent:create agent:assign agent:operate agent:manage agent:delete identity:manage audit:read agent:invoke agent:content:read provider:manage quota:manage usage:read corpus:manage corpus:read"

func price(v int64) *int64 { return &v }

func newID(prefix string) string {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return prefix + "_" + hex.EncodeToString(id[:])
}

// tenantLab is one organization whose identity provider the control plane
// trusts, as controlplane's tests build it.
type tenantLab struct {
	s      *Store
	a      *Accounts
	db     *pgxpool.Pool
	org    CreateOrganizationResponse
	trust  delegatedidentity.Trust
	key    ed25519.PrivateKey
	v      *delegatedidentity.Verifier
	cutoff time.Time
}

// freshStore opens a store on a new schema, migrated, dropped at the test's
// end, and a pool on the same schema.
func freshStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("required PostgreSQL test database is missing")
		}
		t.Skip("run scripts/verify-postgres.py for real PostgreSQL integration checks")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := newID("test")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	scoped := scopedURL(t, dsn, schema)
	s, err := Open(t.Context(), scoped)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	db, err := pgxpool.New(t.Context(), scoped)
	if err != nil {
		s.Close()
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s, db
}

func scopedURL(t *testing.T, dsn, schema string) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema+",pg_catalog")
		u.RawQuery = q.Encode()
		return u.String()
	}
	// schema is generated internally using only SQL-safe identifier characters.
	return cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
}

func organizationInput() CreateOrganizationInput {
	return CreateOrganizationInput{Name: "Engineering", InitialOwner: InitialOrganizationOwner{
		Issuer: "https://issuer.example", Subject: "initial-owner", DisplayName: "Initial Owner"}}
}

// agentLab is an organization whose owner holds agentScopes, with a host
// "local" that can provision its agents.
func agentLab(t *testing.T) (*tenantLab, *AgentCatalog, Principal) {
	t.Helper()
	s, db := freshStore(t)
	a, err := NewAccounts(s, []byte(strings.Repeat("\x42", 32)))
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	platformToken := "acpp_" + base64.RawURLEncoding.EncodeToString(secret)
	if err = s.BootstrapPlatformToken(t.Context(), "platform-test", platformToken, time.Hour); err != nil {
		t.Fatal(err)
	}
	platform, err := s.Authenticate(t.Context(), platformToken)
	if err != nil || platform.Kind != "platform" {
		t.Fatal("platform authentication", err)
	}
	in := organizationInput()
	in.Name += " organization"
	r, err := a.CreateOrganization(t.Context(), platform, "organization", in)
	l := &tenantLab{s: s, a: a, db: db}
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &l.org) != nil {
		t.Fatal("create organization", err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l.key = key
	l.trust = delegatedidentity.Trust{TenantID: l.org.ID, Issuer: in.InitialOwner.Issuer, Audience: "capsule", Keys: map[string]ed25519.PublicKey{"key-1": pub},
		AllowedScopes: strings.Fields(agentScopes), MaxTTL: 5 * time.Minute}
	if l.v, err = delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}}); err != nil {
		t.Fatal(err)
	}
	change, err := s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: "agents-install", Actor: "test-operator", Action: "install",
		TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust})
	if err != nil {
		t.Fatal("authority change", err)
	}
	l.cutoff = change.MinimumIAT
	waitClock(t, l.db, l.cutoff)
	c, err := NewAgentCatalog(a, "local")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterLocalRelease(t.Context(), HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureHostStorage(t.Context(), "local", 4096); err != nil {
		t.Fatal(err)
	}
	return l, c, l.principal(t, in.InitialOwner.Subject, agentScopes)
}

// waitClock waits until the database's clock reaches at.
func waitClock(t *testing.T, db *pgxpool.Pool, at time.Time) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var reached bool
		if err := db.QueryRow(t.Context(), "SELECT clock_timestamp()>=$1::timestamptz", at).Scan(&reached); err != nil {
			t.Fatal(err)
		}
		if reached {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("database clock did not reach activation cutoff")
}

// principal authenticates subject with scopes through the organization's
// trust.
func (l *tenantLab) principal(t *testing.T, subject, scopes string) Principal {
	t.Helper()
	claims := jwt.MapClaims{"iss": l.trust.Issuer, "aud": l.trust.Audience, "sub": subject, "jti": newID("jti"), "iat": l.cutoff.Unix(),
		"exp": l.cutoff.Add(5 * time.Minute).Unix(), "scope": scopes, "role": "platform", "trust_generation": int64(1)}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "key-1"
	raw, err := token.SignedString(l.key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.s.AuthenticateDelegation(t.Context(), l.v, raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func tenantAgentInput(name string) CreateAgentInput {
	return CreateAgentInput{Name: name, Harness: HarnessReference{Name: "reference", Version: "1.0.0"}, Resources: AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 256}}
}

func createTenantAgent(t *testing.T, c *AgentCatalog, p Principal, name string) string {
	t.Helper()
	r, err := c.Reserve(t.Context(), p, "create-"+name, tenantAgentInput(name))
	var created AgentCreation
	if err != nil || r.Status != 202 || json.Unmarshal(r.Body, &created) != nil {
		t.Fatal("create tenant agent", err, r.Status)
	}
	return created.AgentID
}

// activateTenantAgent drives a reservation to LIVE the way the worker does.
func activateTenantAgent(t *testing.T, l *tenantLab, c *AgentCatalog, owner Principal, name string) string {
	t.Helper()
	r, err := c.Reserve(t.Context(), owner, "activate-"+name, tenantAgentInput(name))
	var created AgentCreation
	if err != nil || json.Unmarshal(r.Body, &created) != nil {
		t.Fatal("reserve", err)
	}
	jobs, err := l.s.PendingProvisioning(t.Context(), "local", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range jobs {
		if e.AgentID != created.AgentID {
			continue
		}
		if err = l.s.RecordProvisionedVolume(t.Context(), ProvisionedVolume{AgentID: e.AgentID, OperationID: e.OperationID, VolumeID: e.VolumeID, HostID: e.HostID, Device: 1, Inode: 100}); err != nil {
			t.Fatal(err)
		}
		p, err := l.s.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", time.Minute)
		if err != nil || !p.FenceOnly {
			t.Fatal("restricted claim", err)
		}
		p.VMID = fmt.Sprintf("%016x", p.Generation)
		if err = l.s.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", p.Generation, p.VMID); err != nil {
			t.Fatal(err)
		}
		if err = l.s.RecordEnrollmentInitialized(t.Context(), EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, VolumeID: e.VolumeID, HostID: e.HostID, Generation: p.Generation, VMID: p.VMID}); err != nil {
			t.Fatal(err)
		}
		if err = l.s.BeginPlacementStop(t.Context(), p.AgentID, p.HostID, p.Generation); err != nil {
			t.Fatal(err)
		}
		if err = l.s.ObservePlacementStopped(t.Context(), p.AgentID, p.HostID, p.Generation, true); err != nil {
			t.Fatal(err)
		}
		if err = l.s.ActivateProvisionedAgent(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		return created.AgentID
	}
	t.Fatal("reservation not discoverable")
	return ""
}

func createProvider(t *testing.T, l *tenantLab, p Principal, key string) LLMProvider {
	t.Helper()
	r, err := l.a.CreateLLMProvider(t.Context(), p, key, CreateLLMProviderInput{Name: "main-" + key, Kind: "openai_compatible", BaseURL: "https://llm.example.org/v1", Secret: providerSecret})
	var v LLMProvider
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &v) != nil {
		t.Fatal("create provider", err, r.Status)
	}
	return v
}

// budgetLab is an organization with the alias "fast" (priced per token) and
// two agents, as controlplane's budget tests build it.
type budgetLab struct {
	*tenantLab
	owner Principal
	agent string
	other string
}

func newBudgetLab(t *testing.T) *budgetLab {
	t.Helper()
	l, c, owner := agentLab(t)
	p := createProvider(t, l, owner, "bp")
	if _, err := l.a.CreateLLMAlias(t.Context(), owner, "al1", CreateLLMAliasInput{Alias: "fast", ProviderID: p.ID, UpstreamModel: "m", InputMicroPerMTok: price(1_000_000), OutputMicroPerMTok: price(3_000_000)}); err != nil {
		t.Fatal(err)
	}
	return &budgetLab{tenantLab: l, owner: owner, agent: createTenantAgent(t, c, owner, "a1"), other: createTenantAgent(t, c, owner, "a2")}
}

func (b *budgetLab) budget(t *testing.T, key string, in CreateLLMBudgetInput) LLMBudget {
	t.Helper()
	r, err := b.a.CreateLLMBudget(t.Context(), b.owner, key, in)
	var v LLMBudget
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &v) != nil {
		t.Fatal("create budget", err, r.Status)
	}
	return v
}

func (b *budgetLab) grant(t *testing.T, alias, key string, in CreateLLMAliasGrantInput) LLMAliasGrant {
	t.Helper()
	r, err := b.a.CreateLLMAliasGrant(t.Context(), b.owner, alias, key, in)
	var g LLMAliasGrant
	if err != nil || r.Status != 201 || json.Unmarshal(r.Body, &g) != nil {
		t.Fatal("create grant", err, r.Status)
	}
	return g
}

func (b *budgetLab) access(t *testing.T, alias, key, access string) {
	t.Helper()
	if r, err := b.a.SetLLMAliasAccess(t.Context(), b.owner, alias, key, SetLLMAliasAccessInput{Access: access}); err != nil || r.Status != 200 {
		t.Fatal("set access", err, r.Status)
	}
}

func (b *budgetLab) refusal(t *testing.T, err error) *LLMRefusal {
	t.Helper()
	var r *LLMRefusal
	if !errors.As(err, &r) {
		t.Fatal("not a typed refusal", err)
	}
	return r
}

func (b *budgetLab) usageRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := b.db.QueryRow(t.Context(), `SELECT count(*) FROM llm_usage`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
