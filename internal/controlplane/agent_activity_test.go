package controlplane

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type activity struct {
	at, idle time.Time
	version  uint32 // the row version: changes only when the row is written
}

func readActivity(t *testing.T, s *Store, tx pgx.Tx, agent string) activity {
	t.Helper()
	var a activity
	var idle *time.Time
	const read = "SELECT at,idle_at,xmin::text::bigint FROM agent_activity WHERE agent_id=$1"
	var version int64
	var err error
	if tx != nil {
		err = tx.QueryRow(t.Context(), read, agent).Scan(&a.at, &idle, &version)
	} else {
		err = s.pool.QueryRow(t.Context(), read, agent).Scan(&a.at, &idle, &version)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return activity{}
	}
	if err != nil {
		t.Fatal(err)
	}
	if idle != nil {
		a.idle = *idle
	}
	a.version = uint32(version)
	return a
}

// An agent's last activity is kept in the transaction of the activity itself
// (P-04): an operation, its end, a request sent or received, its decision, a
// model call and its settlement each move it forward; a rolled-back one does
// not; a change that moves no time writes nothing; a purge of old rows leaves
// it. A sleep counts for the eviction order, not for the idle policy.
func TestAgentActivityFollowsItsOperationsRequestsAndModelCalls(t *testing.T) {
	il := newInvocationLab(t)
	ctx := t.Context()
	agent := il.agent
	peer := activateTenantAgent(t, il.tenantLab, il.c, il.owner, "peer")
	start := readActivity(t, il.s, nil, agent)
	if start.at.IsZero() {
		t.Fatal("an activated agent has no activity: its provisioning is one")
	}
	moved := func(what string, before, after activity, idle bool) {
		t.Helper()
		if !after.at.After(before.at) {
			t.Fatalf("%s did not move the activity: %v then %v", what, before.at, after.at)
		}
		if idle != after.idle.After(before.idle) {
			t.Fatalf("%s: idle activity %v then %v", what, before.idle, after.idle)
		}
	}

	// Within the transaction, then gone with its rollback.
	tx, err := il.s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wake := newID("op")
	if _, err = tx.Exec(ctx, `INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind)
        VALUES($1,'someone',$2,'local',900,'wake')`, wake, agent); err != nil {
		t.Fatal(err)
	}
	moved("a wake, in its transaction", start, readActivity(t, il.s, tx, agent), true)
	rollback(tx)
	if got := readActivity(t, il.s, nil, agent); !got.at.Equal(start.at) || !got.idle.Equal(start.idle) {
		t.Fatal("a rolled-back wake left its activity", got, start)
	}

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := il.s.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(sql, err)
		}
	}
	before := readActivity(t, il.s, nil, agent)
	exec(`INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind) VALUES($1,'someone',$2,'local',900,'wake')`, wake, agent)
	after := readActivity(t, il.s, nil, agent)
	moved("a wake", before, after, true)
	before = after
	exec(`UPDATE platform_operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE id=$1`, wake)
	after = readActivity(t, il.s, nil, agent)
	moved("the end of a wake", before, after, true)
	before = after
	exec(`UPDATE platform_operations SET error_code='noted' WHERE id=$1`, wake)
	if after = readActivity(t, il.s, nil, agent); after.version != before.version {
		t.Fatal("a change that moves no time wrote the activity")
	}
	sleep := newID("op")
	exec(`INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind) VALUES($1,'someone',$2,'local',901,'sleep')`, sleep, agent)
	after = readActivity(t, il.s, nil, agent)
	moved("a sleep", before, after, false)

	before = after
	call := newID("llm")
	exec(`INSERT INTO llm_usage(id,tenant_id,agent_id,alias,request_key,reserved_tokens) SELECT $1,tenant_id,id,'model',$1,10 FROM agents WHERE id=$2`, call, agent)
	after = readActivity(t, il.s, nil, agent)
	moved("a model call", before, after, true)
	before = after
	exec(`UPDATE llm_usage SET state='settled',input_tokens=1,output_tokens=1,settled_at=clock_timestamp() WHERE id=$1`, call)
	after = readActivity(t, il.s, nil, agent)
	moved("a model call's settlement", before, after, true)

	before, peerBefore := after, readActivity(t, il.s, nil, peer)
	request := newID("req")
	exec(`INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at) VALUES($1,$2,'activity',1,1,clock_timestamp()+interval '1 hour')`, "mandate-"+request, agent)
	exec(`INSERT INTO agent_requests(id,sender_agent_id,recipient_agent_id,mandate_id,state,via_auto,payload_ref,expires_at)
        VALUES($1,$2,$3,$4,'PENDING_APPROVAL',false,'ref',clock_timestamp()+interval '1 hour')`, request, agent, peer, "mandate-"+request)
	after = readActivity(t, il.s, nil, agent)
	moved("a request sent", before, after, true)
	peerAfter := readActivity(t, il.s, nil, peer)
	moved("a request received", peerBefore, peerAfter, true)
	exec(`UPDATE agent_requests SET decided_at=clock_timestamp() WHERE id=$1`, request)
	moved("a request's decision", peerAfter, readActivity(t, il.s, nil, peer), true)

	// The retention deletes old rows; the activity stays.
	last := readActivity(t, il.s, nil, agent)
	exec(`DELETE FROM platform_operations WHERE id IN ($1,$2)`, wake, sleep)
	if got := readActivity(t, il.s, nil, agent); !got.at.Equal(last.at) || !got.idle.Equal(last.idle) {
		t.Fatal("a purge moved the activity back", got, last)
	}
}

// Migration 0066 fills agent_activity from the history it finds: the latest
// operation, request and end of each agent, the sleeps aside for the idle
// policy.
func TestActivityMigrationFillsFromHistory(t *testing.T) {
	s := migrationStore(t)
	ctx := t.Context()
	at := len(controlPlaneMigrations)
	for i, m := range controlPlaneMigrations {
		if m.name == "open-state-indexes" {
			at = i
		}
	}
	if at == len(controlPlaneMigrations) {
		t.Fatal("no open-state-indexes migration")
	}
	// The tables of the migrations before 0066 (no test of the package runs
	// in parallel).
	all := durableTables
	durableTables = slices.DeleteFunc(slices.Clone(all), func(table string) bool { return table == "agent_activity" })
	err := s.migrate(ctx, controlPlaneMigrations[:at])
	durableTables = all
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s, "auto", 3)
	for _, q := range []string{
		`INSERT INTO worker_hosts(host_id) VALUES('local')`,
		`INSERT INTO platform_operations(id,requested_by_principal_id,agent_id,host_id,seq,kind,status,created_at,completed_at)
         VALUES('op-wake','someone','a','local',1,'wake','SUCCEEDED','2026-01-01 10:00Z','2026-01-01 10:05Z'),
               ('op-sleep','someone','a','local',2,'sleep','SUCCEEDED','2026-01-01 11:00Z','2026-01-01 11:01Z')`,
		`INSERT INTO agent_requests(id,sender_agent_id,recipient_agent_id,mandate_id,state,via_auto,payload_ref,expires_at,created_at,decided_at)
         VALUES('req-1','a','b','mandate-a','EXPIRED',true,'ref','2026-01-01 09:30Z','2026-01-01 09:00Z','2026-01-01 09:20Z')`,
	} {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
	if err := s.migrate(ctx, controlPlaneMigrations); err != nil {
		t.Fatal(err)
	}
	day := func(hour, minute int) time.Time { return time.Date(2026, 1, 1, hour, minute, 0, 0, time.UTC) }
	want := map[string][2]time.Time{"a": {day(11, 1), day(10, 5)}, "b": {day(9, 20), day(9, 20)}}
	for agent, times := range want {
		got := readActivity(t, s, nil, agent)
		at, idle := times[0], times[1]
		if !got.at.Equal(at) || !got.idle.Equal(idle) {
			t.Fatalf("%s: activity %v and %v, want %v and %v", agent, got.at, got.idle, at, idle)
		}
	}
	if got := readActivity(t, s, nil, "c"); !got.at.IsZero() {
		t.Fatal("an agent without history has an activity", got)
	}
}
