package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The fixture of TestInvocationDatabaseRecovery: a fixed schema that
// survives the prepare run, and a fixed signing key, so that the verify run,
// a new process after the crash, signs the same member's tokens again.
const (
	recoverySchema      = "invocation_recovery_probe"
	recoveryKey         = "recovery-invocation"
	recoveryInstruction = "durable before its acknowledgement"
)

func recoverySigner() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5e}, ed25519.SeedSize))
}

// recoveryLab opens the probe's organization: in prepare it creates it, an
// agent that is LIVE and a member assigned to invoke it; in verify it finds
// them again. It returns the lab, the member, the agent and a catalog with
// the transit keys.
func recoveryLab(t *testing.T, s *Store, prepare bool) (*tenantLab, Principal, string, *AgentCatalog, *Transit) {
	t.Helper()
	a, err := NewAccounts(s, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	l := &tenantLab{s: s, a: a, key: recoverySigner()}
	if prepare {
		secret := "acpp_" + tokenSecret()[4:]
		if err = s.BootstrapPlatformToken(t.Context(), "platform-recovery", secret, time.Hour); err != nil {
			t.Fatal(err)
		}
		if l.platform, err = s.Authenticate(t.Context(), secret); err != nil {
			t.Fatal(err)
		}
		l.org = createTestOrganization(t, a, l.platform, "recovery")
	} else if err = s.pool.QueryRow(t.Context(), "SELECT id FROM organizations").Scan(&l.org.ID); err != nil {
		t.Fatal(err)
	}
	l.trust = delegatedidentity.Trust{TenantID: l.org.ID, Issuer: organizationInput().InitialOwner.Issuer, Audience: "capsule",
		Keys: map[string]ed25519.PublicKey{"key-1": l.key.Public().(ed25519.PublicKey)}, AllowedScopes: strings.Fields(agentScopes), MaxTTL: 5 * time.Minute}
	if l.v, err = delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}}); err != nil {
		t.Fatal(err)
	}
	transit, err := NewTransit(s, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x73}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewAgentCatalogWithTransit(a, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	if !prepare {
		// The verify run starts minutes after the trust was installed; its
		// tokens are issued now.
		l.cutoff = time.Now().UTC().Truncate(time.Second)
		var agent string
		if err = s.pool.QueryRow(t.Context(), "SELECT id FROM agents WHERE tenant_id=$1", l.org.ID).Scan(&agent); err != nil {
			t.Fatal(err)
		}
		return l, agentPrincipal(t, l, "bob", userScopes), agent, c, transit
	}
	l.cutoff = l.change(t, "install", "recovery-install", "", &l.trust).MinimumIAT
	waitTenantClock(t, s, l.cutoff)
	if _, err = s.RegisterLocalRelease(t.Context(), HarnessReference{"reference", "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureHostStorage(t.Context(), "local", 4096); err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	owner := agentPrincipal(t, l, organizationInput().InitialOwner.Subject, agentScopes)
	agent := activateTenantAgent(t, l, mustCatalog(t, l), owner, "durable")
	bob := addMember(t, l, owner, "bob", authorization.AgentUser)
	assign(t, l, owner, agent, CreateAssignmentInput{PrincipalID: bob.PrincipalID, Permissions: []string{"read_metadata", "invoke", "read_content"}}, "recovery-assignment")
	return l, agentPrincipal(t, l, "bob", userScopes), agent, c, transit
}

// countingRuntime counts the invocations a harness receives.
type countingRuntime struct {
	instructionRuntime
	invoked atomic.Int32
}

func (r *countingRuntime) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	r.invoked.Add(1)
	return r.instructionRuntime.Invoke(ctx, target, e)
}

// verify-postgres.py invokes this twice, with an immediate shutdown of
// PostgreSQL and its WAL recovery in between (EVT-001): an invocation
// answered 202 survives a database crash right after, with its idempotency
// answer, and is delivered once. The fixture survives the prepare run.
func TestInvocationDatabaseRecovery(t *testing.T) {
	phase := os.Getenv("AGENTCAPSULE_PG_RECOVERY")
	if phase == "" {
		return
	}
	if phase != "prepare" && phase != "verify" {
		t.Fatalf("unknown recovery phase %s", phase)
	}
	rootURL := databaseURL(t)
	admin, err := pgxpool.New(t.Context(), rootURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if phase == "prepare" {
		if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+recoverySchema); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(t.Context(), scopedURL(t, rootURL, recoverySchema))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if phase == "prepare" {
		if err = s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	_, bob, agent, c, transit := recoveryLab(t, s, phase == "prepare")
	r, err := c.CreateInvocation(t.Context(), bob, agent, recoveryKey, InvocationInput{OwnerInstruction: privateInstruction(recoveryInstruction)})
	if err != nil || r.Replayed != (phase == "verify") {
		t.Fatal("acceptance", phase, r.Replayed, err)
	}
	accepted := decodeInvocation(t, r)
	if phase == "prepare" {
		// The 202 has been given: the database stops at once after this.
		return
	}
	// Recovered: the same invocation, its answer replayed, nothing new.
	got, err := c.GetInvocation(t.Context(), bob, accepted.ID)
	if err != nil || got.ID != accepted.ID || got.State != "accepted" || got.AgentID != agent {
		t.Fatal("invocation lost or changed by the crash", got, err)
	}
	var operations, mailboxes int
	if err = s.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM owner_instructions),(SELECT count(*) FROM agent_mailboxes WHERE instruction_id=$1)`,
		accepted.ID).Scan(&operations, &mailboxes); err != nil || operations != 1 || mailboxes != 1 {
		t.Fatal("the replay created work", operations, mailboxes, err)
	}
	// Delivered once: the dispatch hands it to the harness, and nothing is
	// left to deliver.
	head, err := s.HeadDelivery(t.Context(), agent)
	if err != nil {
		t.Fatal(err)
	}
	rt := &countingRuntime{instructionRuntime: instructionRuntimeLab(t, agent)}
	if err = transit.DispatchMailbox(t.Context(), head, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	if _, err = s.HeadDelivery(t.Context(), agent); !errors.Is(err, ErrNoDelivery) {
		t.Fatal("work left after the delivery", err)
	}
	if rt.invoked.Load() != 1 {
		t.Fatal("deliveries", rt.invoked.Load())
	}
	result, err := c.InstructionResult(t.Context(), bob, accepted.ID)
	var out OwnerInstruction
	if err != nil || json.Unmarshal(result, &out) != nil || len(out.Content) != 1 || out.Content[0].Text != recoveryInstruction {
		t.Fatal("result", string(result), err)
	}
	if got, err = c.GetInvocation(t.Context(), bob, accepted.ID); err != nil || got.State != "completed" {
		t.Fatal("completion", got, err)
	}
}
