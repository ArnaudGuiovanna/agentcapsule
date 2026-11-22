package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// admissionLab is an organization with a member, an owner, a technical
// account and its token, and a second key on the trust.
type admissionLab struct {
	*tenantLab
	owner, member Principal
	memberID      string
	service       ServiceAccount
	token         IssuedServiceToken
	bot           Principal
	key2          ed25519.PrivateKey
}

func newAdmissionLab(t *testing.T) *admissionLab {
	t.Helper()
	l, _, owner := agentLab(t)
	a := &admissionLab{tenantLab: l, owner: owner}
	a.memberID = addMember(t, l, owner, "member", authorization.AgentUser).PrincipalID
	a.member = agentPrincipal(t, l, "member", "org:read")
	a.service = newServiceAccount(t, l, owner, "bot", "bot", authorization.AgentUser)
	a.token = issueServiceToken(t, l, owner, a.service.ID, "bot-token", "org:read")
	var err error
	if a.bot, err = l.s.Authenticate(t.Context(), a.token.Token); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a.key2 = key
	if _, err = l.s.ChangeDelegationAuthority(t.Context(), DelegationChange{OperationID: "add-key-2", Actor: "test-operator", Action: "add-key",
		TenantID: l.org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, KeyID: "key-2", PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	return a
}

// admit opens an admission of p: a transaction that authorized p and holds
// what the authorization holds, until it ends.
func admit(t *testing.T, s *Store, p Principal) (pgx.Tx, uint32) {
	t.Helper()
	tx, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authorizeTenant(t.Context(), tx, p, "org:read"); err != nil {
		rollback(tx)
		t.Fatal(err)
	}
	var pid uint32
	if err = tx.QueryRow(t.Context(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		rollback(tx)
		t.Fatal(err)
	}
	return tx, pid
}

// waitBlocked waits until the backend pid blocks another one.
func waitBlocked(t *testing.T, s *Store, pid uint32) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var blocked bool
		if err := s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// P-07: an admission holds its organization's row FOR KEY SHARE and nothing
// else. The organization's row still refuses FOR UPDATE, the lock every
// revocation takes first; its other updates, and every update of the
// principal, the membership, the issuer, the trust, the key and the token,
// no longer wait for the admissions in flight.
func TestAdmissionHoldsOnlyItsOrganizationsRowForKeyShare(t *testing.T) {
	a := newAdmissionLab(t)
	probe := func(t *testing.T, query string, args ...any) error {
		t.Helper()
		tx, err := a.s.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		var one int
		err = tx.QueryRow(t.Context(), query, args...).Scan(&one)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
				t.Fatal(query, err)
			}
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("no row:", query, args)
		}
		return nil
	}
	org := a.org.ID
	for name, p := range map[string]Principal{"a member": a.member, "a technical account": a.bot} {
		t.Run(name, func(t *testing.T) {
			tx, _ := admit(t, a.s, p)
			defer rollback(tx)
			if probe(t, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE NOWAIT`, org) == nil {
				t.Error("a revocation's lock on the organization did not wait for the admission")
			}
			for _, q := range []struct {
				query string
				args  []any
			}{
				{`SELECT 1 FROM organizations WHERE id=$1 FOR NO KEY UPDATE NOWAIT`, []any{org}},
				{`SELECT 1 FROM principals WHERE id=$1 FOR NO KEY UPDATE NOWAIT`, []any{p.ID}},
				{`SELECT 1 FROM memberships WHERE tenant_id=$1 AND principal_id=$2 FOR NO KEY UPDATE NOWAIT`, []any{org, p.ID}},
				{`SELECT 1 FROM delegation_issuers WHERE tenant_id=$1 FOR NO KEY UPDATE NOWAIT`, []any{org}},
				{`SELECT 1 FROM delegation_trusts WHERE tenant_id=$1 FOR NO KEY UPDATE NOWAIT`, []any{org}},
				{`SELECT 1 FROM delegation_keys WHERE tenant_id=$1 AND key_id='key-1' FOR NO KEY UPDATE NOWAIT`, []any{org}},
				{`SELECT 1 FROM service_tokens WHERE id=$1 FOR NO KEY UPDATE NOWAIT`, []any{a.token.ID}},
			} {
				if err := probe(t, q.query, q.args...); err != nil {
					t.Errorf("%s waits for the admission: %v", q.query, err)
				}
			}
		})
	}
}

// P-07, one test per row an admission reads: each revocation waits for an
// admission authorized before it, which commits first; the next admission
// is refused. The replay of a revocation after a failover too: it took no
// lock before.
func TestEachRevocationWaitsForAnAdmissionAuthorizedBeforeIt(t *testing.T) {
	for _, c := range []struct {
		row    string
		who    func(*admissionLab) Principal
		revoke func(context.Context, *admissionLab) error
	}{
		{"organization", func(a *admissionLab) Principal { return a.member }, func(ctx context.Context, a *admissionLab) error {
			_, err := a.a.DisableOrganization(ctx, a.platform, a.org.ID, "disable")
			return err
		}},
		{"membership", func(a *admissionLab) Principal { return a.member }, func(ctx context.Context, a *admissionLab) error {
			_, err := a.a.RevokeMember(ctx, a.owner, a.memberID, "revoke-member")
			return err
		}},
		{"issuer (a token's tombstone)", func(a *admissionLab) Principal { return a.member }, func(ctx context.Context, a *admissionLab) error {
			_, err := a.s.ChangeDelegationAuthority(ctx, DelegationChange{OperationID: "revoke-token", Actor: "test-operator", Action: "revoke-token",
				TenantID: a.org.ID, Issuer: a.trust.Issuer, TokenID: a.member.TokenID})
			return err
		}},
		{"trust", func(a *admissionLab) Principal { return a.member }, func(ctx context.Context, a *admissionLab) error {
			_, err := a.s.ChangeDelegationAuthority(ctx, DelegationChange{OperationID: "revoke-trust", Actor: "test-operator", Action: "revoke-trust",
				TenantID: a.org.ID, Issuer: a.trust.Issuer, Audience: a.trust.Audience})
			return err
		}},
		{"key", func(a *admissionLab) Principal { return a.member }, func(ctx context.Context, a *admissionLab) error {
			_, err := a.s.ChangeDelegationAuthority(ctx, DelegationChange{OperationID: "retire-key-1", Actor: "test-operator", Action: "retire-key",
				TenantID: a.org.ID, Issuer: a.trust.Issuer, Audience: a.trust.Audience, KeyID: "key-1"})
			return err
		}},
		{"service token", func(a *admissionLab) Principal { return a.bot }, func(ctx context.Context, a *admissionLab) error {
			_, err := a.a.RevokeServiceToken(ctx, a.owner, a.service.ID, a.token.ID, "revoke-token")
			return err
		}},
		{"principal (a technical account)", func(a *admissionLab) Principal { return a.bot }, func(ctx context.Context, a *admissionLab) error {
			_, err := a.a.DisableServiceAccount(ctx, a.owner, a.service.ID, "disable-bot")
			return err
		}},
		{"replayed membership", func(a *admissionLab) Principal { return a.member }, func(ctx context.Context, a *admissionLab) error {
			_, err := a.s.replayRecord(ctx, AuthorityRecord{AccessRecord: AccessRecord{ID: newID("arv"), Kind: authoritylog.AccessMember,
				Organization: a.org.ID, Objects: [][]string{{a.memberID}}}, Epoch: 2, Seq: 1})
			return err
		}},
	} {
		t.Run(c.row, func(t *testing.T) {
			a := newAdmissionLab(t)
			p := c.who(a)
			tx, pid := admit(t, a.s, p)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- c.revoke(ctx, a) }()
			if !waitBlocked(t, a.s, pid) {
				rollback(tx)
				<-done
				t.Fatal("the revocation did not wait for the admission")
			}
			if err := commit(t.Context(), tx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := a.a.CurrentOrganization(t.Context(), p); !errors.Is(err, ErrAuthentication) {
				t.Fatal("admitted after the revocation:", err)
			}
		})
	}
}

// P-07, the other order: an admission that arrives while a revocation holds
// the organization's row waits for it, then reads it, whatever row it
// revoked.
func TestAnAdmissionWaitingForARevocationReadsIt(t *testing.T) {
	for _, c := range []struct {
		row    string
		bot    bool
		revoke string
	}{
		{"organization", false, `UPDATE organizations SET status='disabled',policy_version=policy_version+1 WHERE id=$1 AND $2<>''`},
		{"membership", false, `UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND principal_id=$2`},
		{"issuer (a token's tombstone)", false, `INSERT INTO delegation_revocations(tenant_id,issuer,token_id) SELECT $1,issuer,$3 FROM delegation_issuers WHERE tenant_id=$1 AND $2<>''`},
		{"trust", false, `UPDATE delegation_trusts SET status='revoked' WHERE tenant_id=$1 AND $2<>''`},
		{"key", false, `UPDATE delegation_keys SET retired_at=clock_timestamp(),expires_at=clock_timestamp() WHERE tenant_id=$1 AND key_id='key-1' AND $2<>''`},
		{"principal", true, `UPDATE principals SET status='disabled' WHERE tenant_id=$1 AND id=$2`},
		{"service token", true, `UPDATE service_tokens SET revoked_at=clock_timestamp(),revoked_by=issued_by WHERE tenant_id=$1 AND principal_id=$2`},
	} {
		t.Run(c.row, func(t *testing.T) {
			a := newAdmissionLab(t)
			p := a.member
			if c.bot {
				p = a.bot
			}
			tx, err := a.s.begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollback(tx)
			var pid uint32
			if err = tx.QueryRow(t.Context(), `SELECT pg_backend_pid() FROM organizations WHERE id=$1 FOR UPDATE`, a.org.ID).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			args := []any{a.org.ID, p.ID}
			if c.row == "issuer (a token's tombstone)" {
				args = append(args, p.TokenID)
			}
			if _, err = tx.Exec(t.Context(), c.revoke, args...); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := a.a.CurrentOrganization(t.Context(), p); done <- err }()
			if !waitBlocked(t, a.s, pid) {
				t.Fatal("the admission did not wait for the revocation")
			}
			if err = commit(t.Context(), tx); err != nil {
				t.Fatal(err)
			}
			if err = <-done; !errors.Is(err, ErrAuthentication) {
				t.Fatal("an admission that waited did not read the revocation:", err)
			}
		})
	}
}
