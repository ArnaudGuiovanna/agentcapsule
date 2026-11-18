//go:build linux

package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// deadLab is a worker over a real PostgreSQL with no host: agent a, on this
// host, sent agent b requests that b answered. Only a delivery that dies
// without booting its agent can be dispatched here (ADR 007).
type deadLab struct {
	t  *testing.T
	s  *controlplane.Store
	db *pgxpool.Pool
	w  *Placements
}

func newDeadLab(t *testing.T) *deadLab {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("worker_dead_%d", time.Now().UnixNano())
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	s, err := controlplane.Open(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	db, err := pgxpool.New(t.Context(), scoped)
	if err != nil {
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
	for _, id := range []string{"a", "b"} {
		if _, err = db.Exec(t.Context(), `INSERT INTO agents(id,owner_user_id,discoverable,inbound_mode) VALUES($1,$2,true,'auto')`, id, "user-"+id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(t.Context(), `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES('mandate-a','a','owner-instruction',3,3,clock_timestamp()+interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	if err = s.RegisterPlacement(t.Context(), "a", "local"); err != nil {
		t.Fatal(err)
	}
	return &deadLab{t: t, s: s, db: db, w: &Placements{store: s, hostID: "local", workerID: "worker", lease: time.Minute}}
}

// replied returns the mailbox of b's reply to a new request from a.
func (l *deadLab) replied(key string) string {
	l.t.Helper()
	ctx := l.t.Context()
	r, err := l.s.Submit(ctx, "a", key, controlplane.Submission{RecipientAgentID: "b", MandateID: "mandate-a", PayloadRef: "opaque-" + key,
		PayloadHash: sha256.Sum256([]byte(key)), ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)})
	if err != nil {
		l.t.Fatal(err)
	}
	request := l.mailbox(r.RequestID, "request")
	a, err := l.s.ClaimDelivery(ctx, request, time.Minute)
	if err != nil {
		l.t.Fatal(err)
	}
	if err = l.s.AuthorizeDispatch(ctx, request, a.Token); err != nil {
		l.t.Fatal(err)
	}
	if err = l.s.AcknowledgeDelivery(ctx, request, a.Token); err != nil {
		l.t.Fatal(err)
	}
	if _, err = l.s.ReplyToRequest(ctx, "b", r.RequestID, "reply-"+key, controlplane.Reply{Outcome: "completed", PayloadRef: "opaque-reply-" + key,
		PayloadHash: sha256.Sum256([]byte("reply " + key))}); err != nil {
		l.t.Fatal(err)
	}
	return l.mailbox(r.RequestID, "reply")
}

func (l *deadLab) mailbox(request, kind string) string {
	l.t.Helper()
	var id string
	if err := l.db.QueryRow(l.t.Context(), "SELECT id FROM agent_mailboxes WHERE ref_id=$1 AND kind=$2", request, kind).Scan(&id); err != nil {
		l.t.Fatal(err)
	}
	return id
}

func (l *deadLab) pass() {
	l.t.Helper()
	o := DispatchOptions{Batch: 4, WorkLease: time.Minute, DeliveryLease: time.Minute, RetryBase: time.Millisecond, RetryMax: time.Second}
	if err := l.w.DispatchPass(l.t.Context(), o, 10*time.Second); err != nil {
		l.t.Fatal(err)
	}
}

func (l *deadLab) state(id string) string {
	l.t.Helper()
	var state string
	if err := l.db.QueryRow(l.t.Context(), "SELECT delivery_state FROM agent_mailboxes WHERE id=$1", id).Scan(&state); err != nil {
		l.t.Fatal(err)
	}
	return state
}

// A reply that dies is counted, by kind and reason, and logged as
// delivery_dead (ADR 007 §4): one past its deadline, one whose three attempts
// were spent. Every series is served from the start, so that the alert's
// increase() sees the first death.
func TestDeadDeliveryIsCountedAndLogged(t *testing.T) {
	l := newDeadLab(t)
	registry := telemetry.NewRegistry()
	if err := l.w.EnableTelemetry(registry, t.TempDir(), 2); err != nil {
		t.Fatal(err)
	}
	var progress, problems bytes.Buffer
	vocabulary := map[string][]string{"event": {"job_done", "job_retried", "delivery_dead"},
		"kind": append(JobKinds(), DeadDeliveryKinds()...), "reason": append(RetryReasons(), DeadDeliveryReasons()...)}
	if err := l.w.EnableJobEvents(telemetry.NewLogger(&progress, vocabulary), telemetry.NewLogger(&problems, vocabulary)); err != nil {
		t.Fatal(err)
	}
	scrape := func() string {
		rec := httptest.NewRecorder()
		registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
	for _, kind := range DeadDeliveryKinds() {
		for _, reason := range DeadDeliveryReasons() {
			if series := fmt.Sprintf("agentcapsule_worker_deliveries_dead_total{kind=%q,reason=%q} 0\n", kind, reason); !strings.Contains(scrape(), series) {
				t.Fatal("not served from the start:", series)
			}
		}
	}

	expired := l.replied("expired")
	if _, err := l.db.Exec(t.Context(), "UPDATE agent_mailboxes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", expired); err != nil {
		t.Fatal(err)
	}
	l.pass()
	if l.state(expired) != "DEAD" {
		t.Fatal("the expired reply did not die")
	}
	// Three claims that never reached a: the worker crashed before sending.
	exhausted := l.replied("exhausted")
	for range 3 {
		if _, err := l.s.ClaimDelivery(t.Context(), exhausted, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := l.db.Exec(t.Context(), "UPDATE agent_mailboxes SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", exhausted); err != nil {
			t.Fatal(err)
		}
	}
	l.pass()
	if l.state(exhausted) != "DEAD" {
		t.Fatal("the exhausted reply did not die")
	}

	metrics := scrape()
	for _, series := range []string{
		`agentcapsule_worker_deliveries_dead_total{kind="reply",reason="expired"} 1`,
		`agentcapsule_worker_deliveries_dead_total{kind="reply",reason="attempts_exhausted"} 1`,
		`agentcapsule_worker_deliveries_dead_total{kind="status",reason="expired"} 0`,
		`agentcapsule_worker_jobs_total{kind="delivery",outcome="done"} 2`,
	} {
		if !strings.Contains(metrics, series+"\n") {
			t.Fatal("missing", series, "\n", metrics)
		}
	}
	events := problems.String()
	if strings.Count(events, `"event":"delivery_dead"`) != 2 ||
		!strings.Contains(events, `"event":"delivery_dead","kind":"reply","reason":"expired"`) ||
		!strings.Contains(events, `"event":"delivery_dead","kind":"reply","reason":"attempts_exhausted"`) || strings.Contains(events, "invalid") {
		t.Fatal("delivery_dead events", events)
	}
	if strings.Count(progress.String(), `"event":"job_done","kind":"delivery"`) != 2 {
		t.Fatal("the jobs themselves are done", progress.String())
	}
}
