//go:build linux

package worker

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// loopProbe counts the passes of a maintenance loop and lets a test wait for
// them.
type loopProbe struct {
	full, dispatch atomic.Int32
}

func (p *loopProbe) await(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d full passes, %d dispatch passes", what, p.full.Load(), p.dispatch.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func runLoop(t *testing.T, interval time.Duration, wake <-chan struct{}, full, dispatch func(context.Context) bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- maintenanceLoop(ctx, interval, wake, full, dispatch) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != context.Canceled {
			t.Error("the loop ended with", err)
		}
	})
}

// A pass that claimed a full batch is followed at once by another, until a
// pass leaves no more (P-01). The loop used to wait its interval after every
// pass, here an hour.
func TestAFullBatchIsFollowedAtOnceByAnotherPass(t *testing.T) {
	var p loopProbe
	runLoop(t, time.Hour, nil, func(context.Context) bool {
		p.full.Add(1)
		return true
	}, func(context.Context) bool {
		return p.dispatch.Add(1) < 3
	})
	p.await(t, "three passes after the full batch", func() bool { return p.dispatch.Load() == 3 })
	time.Sleep(50 * time.Millisecond)
	if p.dispatch.Load() != 3 || p.full.Load() != 1 {
		t.Fatal("the loop went on without work", p.full.Load(), p.dispatch.Load())
	}
}

// A notification of new work starts a dispatch pass before the interval
// ends; a wake that comes during a pass gives one more pass after it.
func TestAWakeStartsADispatchPass(t *testing.T) {
	var p loopProbe
	wake := make(chan struct{}, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	runLoop(t, time.Hour, wake, func(context.Context) bool {
		p.full.Add(1)
		return false
	}, func(context.Context) bool {
		if p.dispatch.Add(1) == 1 {
			close(started)
			<-release
		}
		return false
	})
	p.await(t, "the first full pass", func() bool { return p.full.Load() == 1 })
	wake <- struct{}{}
	<-started
	wake <- struct{}{} // during the pass
	close(release)
	p.await(t, "a pass for the wake during a pass", func() bool { return p.dispatch.Load() == 2 })
	time.Sleep(50 * time.Millisecond)
	if p.dispatch.Load() != 2 || p.full.Load() != 1 {
		t.Fatal("passes without a wake", p.full.Load(), p.dispatch.Load())
	}
}

// Under a load that never ends, the full passes keep their interval: the
// credential renewals, the storage pressure and the archives still run.
func TestFullPassesKeepTheirIntervalUnderLoad(t *testing.T) {
	var p loopProbe
	runLoop(t, 20*time.Millisecond, nil, func(context.Context) bool {
		p.full.Add(1)
		return true
	}, func(context.Context) bool {
		p.dispatch.Add(1)
		time.Sleep(time.Millisecond)
		return true
	})
	p.await(t, "full passes between dispatch passes", func() bool { return p.full.Load() >= 4 && p.dispatch.Load() >= 4 })
}

// Without business dispatch, a wake changes nothing: one pass per interval.
func TestWithoutDispatchOnlyTheIntervalCounts(t *testing.T) {
	var p loopProbe
	wake := make(chan struct{}, 1)
	wake <- struct{}{}
	runLoop(t, time.Hour, wake, func(context.Context) bool {
		p.full.Add(1)
		return true
	}, nil)
	p.await(t, "the first pass", func() bool { return p.full.Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	if p.full.Load() != 1 {
		t.Fatal("a pass without dispatch did not wait its interval", p.full.Load())
	}
}

// The shipped host configuration polls within seconds: notifications bring
// new work at once, and the poll only bounds what a lost notification costs.
func TestTheShippedConfigurationPollsWithinSeconds(t *testing.T) {
	text, err := os.ReadFile("../../runtime/worker/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	filled := strings.NewReplacer("<restoreauth_PUBLIC_IDENTITY>", "restoreauth_"+strings.Repeat("a", 32),
		"<keyauth_PUBLIC_IDENTITY>", "keyauth_"+strings.Repeat("b", 32)).Replace(string(text))
	c, err := decodeServiceConfig(strings.NewReader(filled))
	if err != nil {
		t.Fatal(err)
	}
	_, _, m, err := c.Settings()
	if err != nil || m.Interval > 10*time.Second {
		t.Fatal("the shipped poll interval", m.Interval, err)
	}
}
