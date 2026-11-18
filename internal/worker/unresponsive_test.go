//go:build linux

package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// transportFailure is a failed RPC as capsuleprotocol's client reports it
// when nothing answered: its sentinel joined with the HTTP client's error.
func transportFailure(cause error) error {
	return errors.Join(capsuleprotocol.ErrTransport, &url.Error{Op: "Post", URL: "https://capsule/v1/fences", Err: cause})
}

// A fence's failure is the guest's, and stops its VM past the attempts,
// only when the guest of a VM booted for work answered that it could not
// fence (its store held: the bare sentinel its error code becomes), or
// nothing answered before the RPC's own timeout while the worker still
// waited. Anything else is the platform's, or a crash's, and stops nothing:
// the worker's own deadline, the host's descriptors, a VMM gone, an
// authority or PostgreSQL, an answer that breaks the protocol, a restricted
// boot.
func TestOnlyAGuestThatDoesNotAnswerItsFenceIsUnresponsive(t *testing.T) {
	work := capsuleprotocol.Identity{AgentID: "agt_a", Generation: 7}
	restricted := work
	restricted.FenceOnly = true
	live := t.Context()
	gone, cancel := context.WithCancel(t.Context())
	cancel()
	for _, c := range []struct {
		name     string
		ctx      context.Context
		identity capsuleprotocol.Identity
		err      error
		guest    bool
	}{
		{"its store held", live, work, capsuleprotocol.ErrTransport, true},
		{"no answer in time", live, work, transportFailure(os.ErrDeadlineExceeded), true},
		{"no answer in time, wrapped", live, work, fmt.Errorf("fence: %w", transportFailure(os.ErrDeadlineExceeded)), true},
		{"the worker gave up", gone, work, transportFailure(context.Canceled), false},
		{"the worker's deadline", gone, work, transportFailure(os.ErrDeadlineExceeded), false},
		{"a VMM gone", live, work, transportFailure(&net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}), false},
		{"the host's descriptors", live, work, transportFailure(&net.OpError{Op: "dial", Net: "unix", Err: syscall.EMFILE}), false},
		{"a restricted boot", live, restricted, capsuleprotocol.ErrTransport, false},
		{"an unknown commit", live, work, harnessstore.ErrCommitUnknown, false},
		{"a broken answer", live, work, capsuleprotocol.ErrProtocol, false},
		{"another boot's answer", live, work, capsuleprotocol.ErrIdentity, false},
		{"an authority", live, work, restoreauthority.ErrStale, false},
		{"PostgreSQL", live, work, errors.New("connection refused by PostgreSQL"), false},
		{"no failure", live, work, nil, false},
	} {
		err := unresponsiveGuest(c.ctx, c.identity, c.err)
		var refused *controlplane.UnresponsiveGuestError
		if got := errors.As(err, &refused); got != c.guest {
			t.Error(c.name, "the guest's", got, err)
			continue
		}
		if c.guest && (refused.Generation != work.Generation || !errors.Is(err, capsuleprotocol.ErrTransport)) {
			t.Error(c.name, "refusal", refused.Generation, err)
		}
		if !c.guest && err != c.err { //nolint:errorlint // returned as is
			t.Error(c.name, "changed", err)
		}
	}
}

// onlyStuckHarness accepts a dispatch pass whose only failures are those of
// a harness that never answers an invocation: an attempt that ended at the
// host's timeout (capsuleprotocol.ErrTransport joined with the HTTP client's
// error) or that the guest refused (the bare sentinel: its store is busy), a
// delivery whose lease is still live, and the next invocation waiting behind
// the held one. Any other failure beside them refuses the pass: a stop or a
// restricted boot that fails among them, or a refused fence that stopped
// nothing, whose cause is the same sentinel.
func onlyStuckHarness(err error) bool {
	if errors.As(err, new(*controlplane.UnresponsiveGuestError)) {
		return false
	}
	return onlyFailures(err, func(e error) bool {
		switch e { //nolint:errorlint // the sentinels themselves, not what wraps them
		case capsuleprotocol.ErrTransport, controlplane.ErrDeliveryBusy, controlplane.ErrNotHead:
			return true
		}
		joined, ok := e.(interface{ Unwrap() []error })
		if !ok {
			return false
		}
		children := joined.Unwrap()
		var request *url.Error
		return len(children) == 2 && children[0] == capsuleprotocol.ErrTransport && errors.As(children[1], &request) //nolint:errorlint // the sentinel itself
	})
}

// The KVM test of a harness that never answers runs passes that fail as
// they must; the errors below have the shapes the worker builds.
func TestPassesOfAGuestThatNeverAnswers(t *testing.T) {
	pass := func(job error) error { return errors.Join(nil, errors.Join(job, nil)) }
	timeout := transportFailure(os.ErrDeadlineExceeded)
	outage := errors.New("database unavailable")
	for _, c := range []struct {
		name string
		err  error
		ok   bool
	}{
		{"an attempt at the host's timeout", pass(timeout), true},
		{"an attempt the busy store refused", pass(capsuleprotocol.ErrTransport), true},
		{"a live lease", pass(controlplane.ErrDeliveryBusy), true},
		{"the next invocation behind it", errors.Join(pass(capsuleprotocol.ErrTransport), pass(controlplane.ErrNotHead)), true},
		{"an attempt and an outage", pass(errors.Join(timeout, outage)), false},
		{"a refused fence that stopped nothing", pass(&controlplane.UnresponsiveGuestError{Generation: 2, Err: capsuleprotocol.ErrTransport}), false},
		{"a restricted boot that failed", pass(controlplane.ErrAgentFailed), false},
		{"an outage", pass(outage), false},
		{"no failure", nil, false},
	} {
		if got := onlyStuckHarness(c.err); got != c.ok {
			t.Error(c.name, got)
		}
	}
}

// A guest that did not answer its fence is stopped like a stuck VM, with
// its quiesce if it answers that, and its VMM's forced removal; the stop
// records a guest failure of kind unresponsive for that boot, counted
// against the restart budget (ADR 012, question 7). The operator sees it by
// kind, and the agent it makes FAILED with the reason unresponsive, never
// the agent. A removal that fails publishes and counts nothing.
func TestAnUnresponsiveGuestIsStoppedAndCounted(t *testing.T) {
	l := newDeadLab(t)
	ctx := t.Context()
	registry := telemetry.NewRegistry()
	if err := l.w.EnableTelemetry(registry, t.TempDir(), 2); err != nil {
		t.Fatal(err)
	}
	var progress, problems bytes.Buffer
	vocabulary := map[string][]string{"event": {"job_done", "job_retried", "agent_failed"},
		"kind": JobKinds(), "reason": append(RetryReasons(), AgentFailureReasons()...)}
	if err := l.w.EnableJobEvents(telemetry.NewLogger(&progress, vocabulary), telemetry.NewLogger(&problems, vocabulary)); err != nil {
		t.Fatal(err)
	}
	if err := l.w.SetRestartBudget(controlplane.RestartBudget{Failures: 1, Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	scrape := func() string {
		rec := httptest.NewRecorder()
		registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
	if series := `agentcapsule_worker_guest_failures_total{kind="unresponsive"} 0`; !strings.Contains(scrape(), series+"\n") {
		t.Fatal("not served from the start:", series)
	}
	if err := l.s.RegisterPlacement(ctx, "b", "local"); err != nil {
		t.Fatal(err)
	}
	placement := func(id string) (state string, unclean bool) {
		t.Helper()
		if err := l.db.QueryRow(ctx, "SELECT state,unclean_stop FROM agent_placements WHERE agent_id=$1", id).Scan(&state, &unclean); err != nil {
			t.Fatal(err)
		}
		return state, unclean
	}
	failures := func(id string) []string {
		t.Helper()
		rows, err := l.db.Query(ctx, "SELECT kind||'/'||generation FROM guest_failures WHERE agent_id=$1 ORDER BY generation", id)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var found []string
		for rows.Next() {
			var f string
			if err = rows.Scan(&f); err != nil {
				t.Fatal(err)
			}
			found = append(found, f)
		}
		return found
	}

	b, err := l.s.ClaimPlacement(ctx, "b", "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	stillThere := errors.New("VMM still alive")
	err = l.w.stopPreparedAs(ctx, "b", b.Generation, nil, func(context.Context) error { return stillThere }, controlplane.GuestUnresponsive)
	if state, _ := placement("b"); !errors.Is(err, stillThere) || state != "STOPPING" || len(failures("b")) != 0 {
		t.Fatal("a removal that failed", state, failures("b"), err)
	}

	a, err := l.s.ClaimPlacement(ctx, "a", "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	retired := false
	err = l.w.stopPreparedAs(ctx, "a", a.Generation, nil, func(ctx context.Context) error {
		if state, _ := placement("a"); state != "STOPPING" {
			t.Fatal("removed before its stop was committed", state)
		}
		retired = true
		return nil
	}, controlplane.GuestUnresponsive)
	if err != nil || !retired {
		t.Fatal("the stop", retired, err)
	}
	if state, unclean := placement("a"); state != "STOPPED" || !unclean {
		t.Fatal("the stopped placement", state, unclean)
	}
	if got := failures("a"); !slices.Equal(got, []string{fmt.Sprintf("%s/%d", controlplane.GuestUnresponsive, a.Generation)}) {
		t.Fatal("guest failures", got)
	}
	if _, err = l.s.ClaimPlacement(ctx, "a", "local", "worker", time.Minute); !errors.Is(err, controlplane.ErrAgentFailed) {
		t.Fatal("a FAILED agent booted", err)
	}
	metrics := scrape()
	for _, series := range []string{`agentcapsule_worker_guest_failures_total{kind="unresponsive"} 1`, `agentcapsule_worker_guest_failures_total{kind="crash"} 0`,
		`agentcapsule_worker_agents_failed_total 1`, `agentcapsule_worker_agents_failed 1`} {
		if !strings.Contains(metrics, series+"\n") {
			t.Fatal("missing", series, "\n", metrics)
		}
	}
	events := problems.String()
	if strings.Count(events, `"event":"agent_failed"`) != 1 || !strings.Contains(events, `"event":"agent_failed","reason":"unresponsive"`) ||
		strings.Contains(events, `"a"`) || strings.Contains(events, "invalid") {
		t.Fatal("agent_failed event", events)
	}
}

// A guest that did not answer its own agent's deletion fence is stopped
// like any unresponsive guest (ADR 012, question 7, sub-question 2), but
// the stop records no guest failure: the agent is being deleted, and a
// restart budget is moot. Even with a budget of one, the agent is not
// FAILED, and the restricted boot that fences its store for the deletion
// can be claimed. The operator still sees the stop among the guests that
// did not answer, with no agent_failed event.
func TestAGuestStoppedForItsAgentsDeletionSpendsNoBudget(t *testing.T) {
	l := newDeadLab(t)
	ctx := t.Context()
	registry := telemetry.NewRegistry()
	if err := l.w.EnableTelemetry(registry, t.TempDir(), 2); err != nil {
		t.Fatal(err)
	}
	var progress, problems bytes.Buffer
	vocabulary := map[string][]string{"event": {"job_done", "job_retried", "agent_failed"},
		"kind": JobKinds(), "reason": append(RetryReasons(), AgentFailureReasons()...)}
	if err := l.w.EnableJobEvents(telemetry.NewLogger(&progress, vocabulary), telemetry.NewLogger(&problems, vocabulary)); err != nil {
		t.Fatal(err)
	}
	if err := l.w.SetRestartBudget(controlplane.RestartBudget{Failures: 1, Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	a, err := l.s.ClaimPlacement(ctx, "a", "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.s.ConfirmPlacement(ctx, "a", "local", "worker", a.Generation, fmt.Sprintf("%016x", a.Generation)); err != nil {
		t.Fatal(err)
	}
	if err = l.s.RequestDeletion(ctx, "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	if err = l.w.stopPreparedAs(ctx, "a", a.Generation, nil, func(context.Context) error { return nil }, controlplane.GuestUnresponsive); err != nil {
		t.Fatal("the stop", err)
	}
	var state string
	var unclean bool
	if err = l.db.QueryRow(ctx, "SELECT state,unclean_stop FROM agent_placements WHERE agent_id='a'").Scan(&state, &unclean); err != nil || state != "STOPPED" || !unclean {
		t.Fatal("the stopped placement", state, unclean, err)
	}
	var failures, failed int
	if err = l.db.QueryRow(ctx, "SELECT (SELECT count(*) FROM guest_failures),(SELECT count(*) FROM failed_agents)").Scan(&failures, &failed); err != nil ||
		failures != 0 || failed != 0 {
		t.Fatal("a failure recorded for an agent being deleted", failures, failed, err)
	}
	if _, err = l.s.ClaimFencePlacement(ctx, "a", "local", "worker", time.Minute); err != nil {
		t.Fatal("the restricted boot of the deletion's fence", err)
	}
	rec := httptest.NewRecorder()
	registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, series := range []string{`agentcapsule_worker_guest_failures_total{kind="unresponsive"} 1`,
		`agentcapsule_worker_agents_failed_total 0`, `agentcapsule_worker_agents_failed 0`} {
		if !strings.Contains(rec.Body.String(), series+"\n") {
			t.Fatal("missing", series, "\n", rec.Body.String())
		}
	}
	if strings.Contains(problems.String(), "agent_failed") {
		t.Fatal("agent_failed for an agent being deleted", problems.String())
	}
}
