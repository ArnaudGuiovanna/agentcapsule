package controlplane

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// roleStore opens a store on s's schema whose every connection acts as role,
// as the installed API or worker does with its own login role: what the store
// runs then needs the privileges migration 0065 and its replacements grant.
func roleStore(t *testing.T, s *Store, role string) *Store {
	t.Helper()
	cfg := s.pool.Config()
	// The store's own hook (it prepares the durability check) runs after.
	prepare := cfg.AfterConnect
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		if _, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize()); err != nil || prepare == nil {
			return err
		}
		return prepare(ctx, c)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &Store{pool: pool}
}

func TestServiceRolesSeparateGuestSubmissionFromOwnerConsent(t *testing.T) {
	serviceRoles(t)
	s, accounts, admin := accountLab(t)
	ctx := t.Context()
	owner := createAccount(t, accounts, admin, "recipient-owner", "Recipient")
	token := issueAccountToken(t, accounts, admin, owner, "recipient-token")
	if _, err := s.pool.Exec(ctx, "UPDATE agents SET owner_user_id=$1 WHERE id='b'", owner.ID); err != nil {
		t.Fatal(err)
	}

	worker := roleStore(t, s, "agentcapsule_worker")
	caller := confirmedCaller(t, s, "a")
	request, err := worker.SubmitFromVM(ctx, caller, "vm-request", submission())
	if err != nil || request.State != PendingApproval {
		t.Fatalf("worker submission: %v, %v", request, err)
	}

	api := roleStore(t, s, "agentcapsule_api")
	principal, err := api.Authenticate(ctx, token.Token)
	if err != nil {
		t.Fatal(err)
	}
	apiAccounts, err := NewAccounts(api, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewAgentCatalog(apiAccounts, "host")
	if err != nil {
		t.Fatal(err)
	}
	consent, err := catalog.DecideRequest(ctx, principal, request.RequestID, "consent", true)
	if err != nil || consent.State != Delivering {
		t.Fatalf("owner consent: %v, %v", consent, err)
	}

	var canLockPlacement, canCreateRequest bool
	err = api.pool.QueryRow(ctx, `SELECT has_table_privilege(current_user, 'agent_placements', 'UPDATE'),
		has_table_privilege(current_user, 'agent_requests', 'INSERT')`).Scan(&canLockPlacement, &canCreateRequest)
	if err != nil || canLockPlacement || canCreateRequest {
		t.Fatalf("API role can update placements: %v, insert requests: %v, error: %v", canLockPlacement, canCreateRequest, err)
	}
}

// agent_activity is kept by the triggers of the tables each process writes
// (migration 0071). A trigger runs with the privileges of the role whose
// statement fired it (none is SECURITY DEFINER), so each service role keeps
// the activity of its own writes; neither may delete from it (migration
// 0073: the default privileges gave both DELETE).
func TestServiceRolesKeepTheActivityThroughTheTriggers(t *testing.T) {
	serviceRoles(t)
	s, _ := freshStore(t, "auto", 3)
	ctx := t.Context()
	if _, err := s.pool.Exec(ctx, `INSERT INTO worker_hosts(host_id) VALUES('local')`); err != nil {
		t.Fatal(err)
	}
	for i, role := range serviceRoleNames {
		before := readActivity(t, s, nil, "a")
		r := roleStore(t, s, role)
		op := newID("op")
		if _, err := r.pool.Exec(ctx, `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind)
            VALUES($1,'someone','a','local',$2,'wake')`, op, 100+i); err != nil {
			t.Fatalf("%s: a wake: %v", role, err)
		}
		if _, err := r.pool.Exec(ctx, `UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE id=$1`, op); err != nil {
			t.Fatalf("%s: the end of a wake: %v", role, err)
		}
		if after := readActivity(t, s, nil, "a"); !after.at.After(before.at) || !after.idle.After(before.idle) {
			t.Fatalf("%s: the activity did not follow its writes: %v then %v", role, before, after)
		}
		_, err := r.pool.Exec(context.WithoutCancel(ctx), `DELETE FROM agent_activity WHERE agent_id='a'`)
		if !refused(err) {
			t.Errorf("%s deleted an activity: %v", role, err)
		}
	}
}
