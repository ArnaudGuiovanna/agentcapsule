//go:build linux && cgo

package api

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// A PostgreSQL backup taken while an agent was still free can be restored
// after Alice has received its volume. Reconcile the authority stream before
// opening the restored API to Bob, keeping that volume outside every grant.
func TestRestoreBeforePersonalVolumeAllocation(t *testing.T) {
	f := newRBACFixture(t)
	ctx := t.Context()
	var schema string
	if err := f.db.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(schema, "api_") && !strings.HasPrefix(schema, "test_") {
		t.Fatal("backup qualification requires a dedicated test schema", schema)
	}
	dbTool := func(name string, args ...string) {
		t.Helper()
		bin := name
		if dir := os.Getenv("AGENTCAPSULE_TEST_PG_BIN"); dir != "" {
			bin = filepath.Join(dir, name)
		} else if _, err := exec.LookPath(bin); err != nil {
			t.Skip("set AGENTCAPSULE_TEST_PG_BIN to qualify with pg_dump and pg_restore")
		}
		cmd := exec.CommandContext(ctx, bin, args...)
		cfg := f.db.Config().ConnConfig
		cmd.Env = append(os.Environ(), "PGDATABASE="+cfg.Database, "PGHOST="+cfg.Host, fmt.Sprintf("PGPORT=%d", cfg.Port), "PGUSER="+cfg.User, "PGPASSWORD="+cfg.Password)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
	}
	v := appFixture(t, f)
	pool := f.ids["pool"]
	var agent, volume string
	if err := f.db.QueryRow(ctx, "SELECT m.agent_id,e.volume_id FROM agent_pool_members m JOIN store_enrollments e USING(agent_id) WHERE pool_id=$1", pool).Scan(&agent, &volume); err != nil {
		t.Fatal(err)
	}
	apiProvisionAgent(t, f.l, agent)
	apiRoot := "/v1/applications/" + v["app"]
	var policy controlplane.AssignmentPolicy
	slot := controlplane.PolicySlot{Name: "personal", PoolID: pool, Permissions: []string{"invoke", "read_metadata", "read_content"}}
	f.must(t, "owner", "POST", "/v1/assignment-policies/plan", stringify(controlplane.PolicySpec{ApplicationID: v["app"], OnExhaustion: "refuse", Slots: []controlplane.PolicySlot{slot}}), 201, &policy)
	f.must(t, "owner", "POST", "/v1/assignment-policies/"+policy.ID+"/apply", "{}", 200, nil)
	invite := func(who string) string {
		var invitation controlplane.Invitation
		f.must(t, "owner", "POST", apiRoot+"/invitations", stringify(controlplane.InviteInput{PolicyID: policy.ID, Email: who + "@example.test", ExpiresAt: time.Now().Add(time.Hour)}), 201, &invitation)
		return stringify(controlplane.AcceptInvitation{Proof: invitation.Proof})
	}
	alice, bob := invite("alice"), invite("bob")
	archive := filepath.Join(t.TempDir(), "before.dump")
	dbTool("pg_dump", "--schema="+schema, "--format=custom", "--file="+archive)
	authority := &fakeAuthority{onReplica: true}
	f.l.store.RecordAccessWith(authority)
	accept := func(who, proof string, want int) controlplane.Activation {
		t.Helper()
		token := signAppToken(t, v["issuer"], who, "agentcapsule-api")
		r := call(t, f.server, "POST", apiRoot+"/accept", token, who, proof)
		if r.Code != want {
			t.Fatalf("accept %s: %d %s", who, r.Code, r.Body.String())
		}
		var a controlplane.Activation
		if err := json.Unmarshal(r.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	authority.set(false, true, nil)
	accept("alice", alice, 503)
	if n := scalar[int](t, f.l, "SELECT count(*) FROM app_personal_reservations"); n != 0 {
		t.Fatal("degraded authority released a personal volume")
	}
	unconfirmed := authority.recorded()
	authority = &fakeAuthority{onReplica: true}
	f.l.store.RecordAccessWith(authority)
	a := accept("alice", alice, 200)
	recs := authority.recorded()
	if len(unconfirmed) != 1 || len(recs) != 1 || stringify(unconfirmed[0]) != stringify(recs[0]) || a.Agents["personal"] != agent || recs[0].Kind != authoritylog.AccessPersonalVolume || fmt.Sprint(recs[0].Objects) != fmt.Sprint([][]string{{agent, volume, a.PrincipalID}}) {
		t.Fatal("unexpected volume hold", a, recs)
	}
	dbTool("pg_restore", "--clean", "--if-exists", "--single-transaction", "--no-owner", "--dbname="+f.db.Config().ConnConfig.Database, archive)
	f.db.Reset()
	if n := scalar[int](t, f.l, "SELECT count(*) FROM app_personal_reservations"); n != 0 {
		t.Fatal("backup already contains a reservation")
	}
	r, err := f.l.store.Reconcile(ctx, &replayAuthority{records: recs})
	if err != nil || r.Replayed != 1 {
		t.Fatal("reconcile", r, err)
	}
	// Repeat the same physical recovery without an epoch change. The API's
	// startup path must quarantine Alice's volume before serving requests.
	dbTool("pg_restore", "--clean", "--if-exists", "--single-transaction", "--no-owner", "--dbname="+f.db.Config().ConnConfig.Database, archive)
	f.db.Reset()
	if err := f.l.store.SyncPersonalVolumeHolds(ctx, &replayAuthority{records: recs}); err != nil {
		t.Fatal("same-epoch restore", err)
	}
	accept("bob", bob, 409)
	var inventory controlplane.AgentPool
	f.must(t, "owner", "GET", "/v1/pools/"+pool, "", 200, &inventory)
	if inventory.Available != 0 {
		t.Fatal("private volume exposed in restored pool", inventory)
	}
	target := f.ids["user_principal"]
	body := stringify(controlplane.CreateAssignmentInput{PrincipalID: target, Permissions: []string{"read_content"}})
	f.must(t, "owner", "POST", "/v1/agents/"+agent+"/assignments", body, 409, nil)
	f.must(t, "owner", "POST", "/v1/pools/"+pool+"/expand", `{"count":1}`, 200, nil)
	if b := accept("bob", bob, 200); b.Agents["personal"] == agent || b.Agents["personal"] == "" {
		t.Fatal("restored volume assigned to another member", b)
	}
}
