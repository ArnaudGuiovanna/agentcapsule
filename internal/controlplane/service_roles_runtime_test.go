package controlplane

import (
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
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &Store{pool: pool}
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
