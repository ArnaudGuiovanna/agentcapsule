//go:build linux

package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The database of the KVM labs: the placement, control, dispatch, platform
// and seal tests, which only verify-runtime.py runs, as root. It lives outside
// their build tags so that the PostgreSQL campaign checks it without KVM.

// database opens a store on schema, migrated, and an administration pool with
// the default search path, which does not hold schema. With create, it makes
// the schema and the agents a, b and c, each of a person (no organization).
func database(t *testing.T, schema string, create bool) (*controlplane.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		t.Fatal("real PostgreSQL is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",pg_catalog"
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if create {
		if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	s, err := controlplane.Open(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if create {
		for _, id := range []string{"a", "b", "c"} {
			if _, err = admin.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{schema, "agents"}.Sanitize()+"(id,owner_user_id) VALUES ($1,$2)", id, "user-"+id); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { s.Close(); admin.Close() })
	return s, admin
}

// specifyAgent gives a lab agent what every agent created through the API
// has: a spec on host, pinned to a release whose manifest predates the
// capabilities, so that it holds every capability (ADR 016). The platform
// channel refuses the gated calls of an agent without one: not_found.
func specifyAgent(t *testing.T, db *pgxpool.Pool, schema, host, id string) {
	t.Helper()
	if _, err := db.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{schema, "worker_hosts"}.Sanitize()+"(host_id) VALUES ($1) ON CONFLICT DO NOTHING", host); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{schema, "harness_releases"}.Sanitize()+
		"(id,name,version,artifact_digest,source) VALUES ('rel_kvm_lab','kvm-lab','1','sha256:'||repeat('0',64),'local-approved') ON CONFLICT DO NOTHING"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{schema, "agent_specs"}.Sanitize()+
		"(agent_id,name,release_id,host_id,vcpus,memory_mib,volume_mib,auto_start) VALUES ($1,$1,'rel_kvm_lab',$2,1,256,128,false)", id, host); err != nil {
		t.Fatal(err)
	}
}

// The lab's agents as its KVM tests use them: changed through the
// administration pool, and calling the platform channel's gated routes.
func TestKVMLabAgentsMayUseThePlatform(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_TEST_POSTGRES") == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	schema := fmt.Sprintf("kvm_lab_%d", time.Now().UnixNano())
	s, db := database(t, schema, true)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := db.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	// The Directory's triggers find their table whatever the session's search
	// path (migration 0048): the first statement of most control tests.
	for _, change := range []string{"SET inbound_mode='auto',discoverable=true", "SET phase='DELETING' WHERE id='c'"} {
		if _, err := db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agents"}.Sanitize()+" "+change); err != nil {
			t.Fatal(change, err)
		}
	}
	specifyAgent(t, db, schema, "host", "a")
	for _, name := range []string{capability.AgentsDelegate, capability.AgentsDiscover} {
		if err := s.RequireCapabilityFromVM(t.Context(), controlplane.VMCaller{AgentID: "a"}, name); err != nil {
			t.Error("a specified agent is refused", name, err)
		}
	}
	// An agent without a spec, which the API never creates, holds none.
	if err := s.RequireCapabilityFromVM(t.Context(), controlplane.VMCaller{AgentID: "b"}, capability.AgentsDelegate); !errors.Is(err, controlplane.ErrNotFound) {
		t.Error("an agent without a spec:", err)
	}
}
