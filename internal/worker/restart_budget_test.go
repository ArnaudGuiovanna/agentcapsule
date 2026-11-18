//go:build linux

package worker

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// onlyBootFailures accepts a dispatch pass whose only failures are boots that
// the guest failed: runtime.ErrBootFailed joined with its cause, as the host
// classifies them (ADR 012). Any other failure beside them refuses the pass.
func onlyBootFailures(err error) bool {
	return onlyFailures(err, func(e error) bool {
		joined, ok := e.(interface{ Unwrap() []error })
		return ok && slices.Contains(joined.Unwrap(), runtime.ErrBootFailed)
	})
}

// onlyAgentFailed accepts a dispatch pass whose only failures are work that
// waits for a FAILED agent.
func onlyAgentFailed(err error) bool {
	return onlyFailures(err, func(e error) bool { return e == controlplane.ErrAgentFailed })
}

// onlyFailures reports whether err, the joined error of a dispatch pass, holds
// failures that one accepts and nothing else. It looks through joins and
// wraps down to each failure; any other leaf refuses the whole.
func onlyFailures(err error, one func(error) bool) bool {
	switch {
	case err == nil:
		return false
	case one(err):
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyFailures(child, one) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyFailures(wrapped.Unwrap(), one)
	}
	return false
}

// A KVM test of a guest that crashes at boot runs dispatch passes that fail,
// as they must: each boot the guest fails is the job's failure and the
// pass's, and so is each attempt to deliver to the FAILED agent. The test
// accepts those failures and no other, even joined with them. The errors
// below have the shapes the worker builds: the host's classification
// (bootFailure), its cleanup join (fail), the worker's join with the
// failure's record (startRenewal), and the pass's joins (DispatchPass).
func TestPassesOfAGuestThatFailsAtBoot(t *testing.T) {
	pass := func(job error) error { return errors.Join(nil, errors.Join(job, nil)) }
	cause := errors.New("volume bootstrap rejected or unavailable")
	bootFailed := errors.Join(errors.Join(errors.Join(runtime.ErrBootFailed, cause), nil), nil)
	outage := errors.New("database unavailable")
	for _, c := range []struct {
		name        string
		err         error
		boot, agent bool
	}{
		{"a boot the guest failed", pass(bootFailed), true, false},
		{"two of them", errors.Join(pass(bootFailed), pass(bootFailed)), true, false},
		{"its record failed too", pass(errors.Join(bootFailed, outage)), false, false},
		{"its cleanup failed too", pass(errors.Join(errors.Join(runtime.ErrBootFailed, cause), outage)), false, false},
		{"a failed start that is not the guest's", pass(errors.Join(errors.Join(cause, nil), nil)), false, false},
		{"a delivery held for a FAILED agent", pass(controlplane.ErrAgentFailed), false, true},
		{"wrapped", pass(fmt.Errorf("deliver: %w", controlplane.ErrAgentFailed)), false, true},
		{"with its wake not given back", pass(errors.Join(controlplane.ErrAgentFailed, outage)), false, false},
		{"a boot failure while FAILED", errors.Join(pass(controlplane.ErrAgentFailed), pass(bootFailed)), false, false},
		{"another failure", pass(outage), false, false},
		{"no failure", nil, false, false},
	} {
		if got := onlyBootFailures(c.err); got != c.boot {
			t.Error(c.name, "onlyBootFailures", got)
		}
		if got := onlyAgentFailed(c.err); got != c.agent {
			t.Error(c.name, "onlyAgentFailed", got)
		}
	}
}

// procIOMoved sums rchar and wchar in the text of /proc/<pid>/io: the bytes
// a process moved through read and write system calls.
func procIOMoved(io string) (int64, error) {
	var moved int64
	found := 0
	for _, line := range strings.Split(io, "\n") {
		name, value, ok := strings.Cut(line, ": ")
		if !ok || name != "rchar" && name != "wchar" {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid /proc/<pid>/io line %q", line)
		}
		moved += n
		found++
	}
	if found != 2 {
		return 0, errors.New("/proc/<pid>/io without rchar and wchar")
	}
	return moved, nil
}

// The drive ceiling KVM test reads what a VMM moved from /proc/<pid>/io; this
// process's own count grows by what it writes and reads back.
func TestProcIOMovedCountsReadsAndWrites(t *testing.T) {
	if _, err := procIOMoved("rchar: 1\nsyscr: 2\n"); err == nil {
		t.Fatal("accepted a text without wchar")
	}
	if _, err := procIOMoved("rchar: 1\nwchar: -2\n"); err == nil {
		t.Fatal("accepted a negative count")
	}
	moved := func() int64 {
		t.Helper()
		b, err := os.ReadFile("/proc/self/io")
		if err != nil {
			t.Fatal(err)
		}
		n, err := procIOMoved(string(b))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	path := filepath.Join(t.TempDir(), "moved")
	before := moved()
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || len(b) != 1<<20 {
		t.Fatal(len(b), err)
	}
	if delta := moved() - before; delta < 2<<20 {
		t.Fatal("1 MiB written and read back, moved", delta)
	}
}
