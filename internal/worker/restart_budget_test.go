//go:build linux

package worker

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The operator learns of guest failures and FAILED agents (ADR 012):
// failures by kind, agents that spent their budget, how many are FAILED now,
// and one agent_failed event with the reason, never the agent. Every series is
// served from the start, so that the alert's increase() sees the first one.
func TestGuestFailuresAreCountedAndLogged(t *testing.T) {
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
	if err := l.w.SetRestartBudget(controlplane.RestartBudget{}); !errors.Is(err, controlplane.ErrInput) {
		t.Fatal("an invalid budget", err)
	}
	if l.w.restartBudget() != controlplane.DefaultRestartBudget {
		t.Fatal("default budget", l.w.restartBudget())
	}
	if err := l.w.SetRestartBudget(controlplane.RestartBudget{Failures: 2, Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	scrape := func() string {
		rec := httptest.NewRecorder()
		registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
	for _, series := range []string{`agentcapsule_worker_guest_failures_total{kind="boot"} 0`, `agentcapsule_worker_guest_failures_total{kind="crash"} 0`,
		`agentcapsule_worker_agents_failed_total 0`, `agentcapsule_worker_agents_failed 0`} {
		if !strings.Contains(scrape(), series+"\n") {
			t.Fatal("not served from the start:", series)
		}
	}
	fail := func(kind string) {
		t.Helper()
		p, err := l.s.ClaimPlacement(ctx, "a", "local", "worker", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err = l.w.observeGuestFailure(ctx, "a", p.Generation, kind); err != nil {
			t.Fatal(err)
		}
	}
	fail(controlplane.GuestBootFailed)
	if strings.Contains(problems.String(), "agent_failed") {
		t.Fatal("FAILED within its budget", problems.String())
	}
	fail(controlplane.GuestCrashed)
	if _, err := l.s.ClaimPlacement(ctx, "a", "local", "worker", time.Minute); !errors.Is(err, controlplane.ErrAgentFailed) {
		t.Fatal("a FAILED agent booted", err)
	}
	metrics := scrape()
	for _, series := range []string{`agentcapsule_worker_guest_failures_total{kind="boot"} 1`, `agentcapsule_worker_guest_failures_total{kind="crash"} 1`,
		`agentcapsule_worker_agents_failed_total 1`, `agentcapsule_worker_agents_failed 1`} {
		if !strings.Contains(metrics, series+"\n") {
			t.Fatal("missing", series, "\n", metrics)
		}
	}
	events := problems.String()
	if strings.Count(events, `"event":"agent_failed"`) != 1 || !strings.Contains(events, `"event":"agent_failed","reason":"crashed"`) ||
		strings.Contains(events, `"a"`) || strings.Contains(events, "invalid") {
		t.Fatal("agent_failed event", events)
	}
}

// Configured budgets and drive ceilings: absent means the defaults, a number
// left out takes its default, and values out of bounds are refused.
func TestRestartBudgetAndDriveLimitsConfiguration(t *testing.T) {
	c := ServiceConfig{Version: 1, HostID: "host", BootTimeout: "30s", BootLease: "2m", PollInterval: "1s", AttemptTimeout: "45s"}
	if b, err := c.Restarts(); err != nil || b != controlplane.DefaultRestartBudget {
		t.Fatal("default budget", b, err)
	}
	opts, _, _, err := c.Settings()
	if err != nil || opts.DriveLimits.Volume.BandwidthMiBPerSecond != 64 || opts.DriveLimits.Harness.IOPS != 4000 {
		t.Fatal("default drive limits", opts.DriveLimits, err)
	}
	c.RestartBudget = &ServiceRestartBudget{Failures: 3}
	if b, err := c.Restarts(); err != nil || b.Failures != 3 || b.Window != time.Hour {
		t.Fatal("partial budget", b, err)
	}
	c.RestartBudget = &ServiceRestartBudget{Failures: 10, Window: "15m"}
	if b, err := c.Restarts(); err != nil || b.Failures != 10 || b.Window != 15*time.Minute {
		t.Fatal("budget", b, err)
	}
	for _, bad := range []ServiceRestartBudget{{Failures: 101}, {Failures: -1}, {Window: "30s"}, {Window: "25h"}, {Window: "soon"}} {
		c.RestartBudget = &bad
		if _, _, _, err = c.Settings(); err == nil {
			t.Fatal("accepted budget", bad)
		}
	}
	c.RestartBudget = nil
	c.DriveLimits = &runtime.DriveLimits{Volume: runtime.DriveRate{BandwidthMiBPerSecond: 8}}
	if opts, _, _, err = c.Settings(); err != nil || opts.DriveLimits.Volume.BandwidthMiBPerSecond != 8 || opts.DriveLimits.Volume.IOPS != 2000 ||
		opts.DriveLimits.Harness.BandwidthMiBPerSecond != 128 {
		t.Fatal("partial drive limits", opts.DriveLimits, err)
	}
	c.DriveLimits = &runtime.DriveLimits{Harness: runtime.DriveRate{IOPS: 5}}
	if _, _, _, err = c.Settings(); err == nil {
		t.Fatal("accepted 5 operations a second")
	}
}
