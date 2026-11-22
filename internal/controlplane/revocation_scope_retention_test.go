package controlplane

import (
	"slices"
	"testing"
)

// scopeOf is the scope RevocationScopes gives subject.
func scopeOf(t *testing.T, s *Store, subject string) []string {
	t.Helper()
	scopes, err := s.RevocationScopes(t.Context(), []string{subject})
	if err != nil || len(scopes) != 1 || scopes[0].Subject != subject {
		t.Fatal("the scope of", subject, scopes, err)
	}
	return scopes[0].Stores
}

// addressedNaming counts the mailbox entries PostgreSQL still holds for dest
// whose event names agent/<agent>: the events of a request between them
// (delivery.go, peer_payloads.go).
func addressedNaming(t *testing.T, s *Store, dest, agent string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(t.Context(), `SELECT count(*) FROM agent_mailboxes m JOIN agent_requests r ON r.id=m.ref_id
        WHERE m.dest_agent_id=$1 AND $2 IN (r.sender_agent_id,r.recipient_agent_id)`, dest, agent).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// FIX-1, after the retention of finished records (P-04). A request between a
// and b, answered, whose reply's delivery died, goes with its mailbox entries
// past its retention.
//
//   - The dead reply's event/<id> subject keeps its destination as its scope:
//     it is recorded with the subject. Before, read from the purged mailbox
//     entry, it had no store, so the authority put it in every store's scope,
//     and its ID reached the guests of every organization.
//   - agent/a's scope no longer holds b, and that is safe: PostgreSQL holds no
//     event for b that names a, and can make none (a request joins only LIVE
//     agents); b answered the request, before any archive a restore can start
//     from (the retention exceeds their horizon).
func TestRetentionKeepsTheScopeOfARevokedEventAndNarrowsOnlyWhatNoStoreActsOn(t *testing.T) {
	l := newDeadReplyLab(t)
	l.killReply(t)
	event := "event/" + l.reply
	if got := scopeOf(t, l.s, event); !slices.Equal(got, []string{"a"}) {
		t.Fatal("the dead reply's scope before the purge", got)
	}
	if got := scopeOf(t, l.s, "agent/a"); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatal("agent/a's scope before the purge", got)
	}
	// The contents' own retention has passed.
	if _, err := l.s.pool.Exec(t.Context(), `UPDATE transit_payloads SET ciphertext=NULL,purged_at=clock_timestamp()
        WHERE kind IN ('request','reply') AND ref_id=$1`, l.request); err != nil {
		t.Fatal(err)
	}
	if n, err := l.s.PurgeFinished(t.Context(), "host", pastRetention(), MinFinishedRetention, 100); err != nil || n.Requests != 1 {
		t.Fatal("the purge past the retention", n, err)
	}
	var kept int
	if err := l.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM agent_mailboxes WHERE id=$1", l.reply).Scan(&kept); err != nil || kept != 0 {
		t.Fatal("the dead reply's mailbox entry was kept", kept, err)
	}
	if got := scopeOf(t, l.s, event); !slices.Equal(got, []string{"a"}) {
		t.Fatal("the dead reply's scope after the purge: no store means every organization's", got)
	}
	if got := scopeOf(t, l.s, "agent/a"); !slices.Equal(got, []string{"a"}) {
		t.Fatal("agent/a's scope after the purge", got)
	}
	if addressedNaming(t, l.s, "b", "a") != 0 {
		t.Fatal("an event for b still names a")
	}
}

// A closed request's request/<id> subject keeps its two parties as its scope
// after the purge of the request (FIX-1): every event of the request names
// that subject, so its closure's fence in both parties covers what the
// retention removed from agent/a's scope.
func TestRetentionKeepsTheScopeOfAClosedRequest(t *testing.T) {
	serviceRoles(t)
	s, _ := freshStore(t, "auto", 5)
	worker := roleStore(t, s, "agentcapsule_worker")
	ctx := t.Context()
	if _, err := s.pool.Exec(ctx, `INSERT INTO agent_placements(agent_id,host_id) VALUES('a','local'),('b','local')`); err != nil {
		t.Fatal(err)
	}
	m := mockStores(t, t.TempDir(), "a", "b")
	m.SetHandler(recordDelivery)
	r, err := s.Submit(ctx, "a", "closed", submission())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RequestCancellation(ctx, "user-a", r.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileRequestClosure(ctx, r.RequestID, m); err != nil {
		t.Fatal(err)
	}
	subject := "request/" + r.RequestID
	if _, err = s.pool.Exec(ctx, `UPDATE agent_mailboxes SET delivery_state='DELIVERED' WHERE kind='status' AND ref_id=$1`, r.RequestID); err != nil {
		t.Fatal(err)
	}
	if n, err := worker.PurgeFinished(ctx, "local", pastRetention(), MinFinishedRetention, 100); err != nil || n.Requests != 1 {
		t.Fatal("the purge past the retention", n, err)
	}
	if got := scopeOf(t, s, subject); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatal("the closed request's scope after the purge", got)
	}
	if got := scopeOf(t, s, "agent/a"); !slices.Equal(got, []string{"a"}) {
		t.Fatal("agent/a's scope after the purge", got)
	}
	if addressedNaming(t, s, "b", "a") != 0 {
		t.Fatal("an event for b still names a")
	}
}

// Migration revocation-subject-stores records the stores of the request/ and
// event/ subjects already in the catalogue, from their rows, and none for an
// agent/ subject or a subject whose row is gone; the catalogue's guard is on
// again after it.
func TestTheMigrationRecordsTheStoresOfExistingSubjects(t *testing.T) {
	s := migrationStore(t)
	ctx := t.Context()
	at := slices.IndexFunc(controlPlaneMigrations, func(m schemaMigration) bool { return m.name == "revocation-subject-stores" })
	if at < 0 {
		t.Fatal("no revocation-subject-stores migration")
	}
	if err := s.migrate(ctx, controlPlaneMigrations[:at]); err != nil {
		t.Fatal(err)
	}
	seed(t, s, "auto", 3)
	request := partner(t, s, "a", "b")
	for _, q := range []string{
		`INSERT INTO agent_mailboxes(id,dest_agent_id,seq,kind,ref_id,expires_at) VALUES('mbx-1','b',1,'request','` + request + `',clock_timestamp()+interval '1 hour')`,
		`INSERT INTO revocation_catalogue(subject) VALUES('event/mbx-1'),('request/` + request + `'),('agent/a'),('event/mbx-gone'),('request/gone')`,
	} {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
	if err := s.migrate(ctx, controlPlaneMigrations); err != nil {
		t.Fatal(err)
	}
	for subject, want := range map[string][]string{
		"event/mbx-1": {"b"}, "request/" + request: {"a", "b"}, "agent/a": nil, "event/mbx-gone": nil, "request/gone": nil,
	} {
		var got []string
		if err := s.pool.QueryRow(ctx, `SELECT stores FROM revocation_catalogue WHERE subject=$1`, subject).Scan(&got); err != nil || !slices.Equal(got, want) {
			t.Errorf("%s: stores %v, want %v (%v)", subject, got, want, err)
		}
	}
	if _, err := s.pool.Exec(ctx, `UPDATE revocation_catalogue SET stores=ARRAY['c'] WHERE subject='agent/a'`); !refused(err) {
		t.Fatal("the catalogue's guard is off after the migration", err)
	}
}
