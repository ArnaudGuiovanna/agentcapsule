//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// replayDeadLetter puts an instruction that died without reaching its agent
// back in its agent's queue (ADR 017): the same identifier and event ID, a new
// attempt budget, its deadline kept or a new window. The key makes the command
// safe to run again: the same key returns the first replay.
func replayDeadLetter(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("replay-dead-letter", flag.ContinueOnError)
	operation := f.String("operation-id", "", "the dead letter's invocation (operation) identifier")
	key := f.String("key", "", "idempotency key of this replay")
	ttl := f.Duration("ttl", 0, "new delivery window from now (1s to 24h); without it the deadline is kept")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *operation == "" || *key == "" || *ttl < 0 || *ttl%time.Second != 0 {
		return fail("configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	r, err := s.ReplayDeadInstruction(ctx, *operation, *key, controlplane.ReplayInput{TTLSeconds: int(*ttl / time.Second)})
	if err != nil {
		if reason, definite := replayRefusal(err); definite {
			return fail("replay_dead_letter_rejected_" + reason)
		}
		return fail("replay_dead_letter_unconfirmed_retry_same_command")
	}
	out, err := json.Marshal(struct {
		controlplane.Replay
		Again bool `json:"already_replayed"`
	}{r, r.Replayed})
	if err != nil {
		return fail("replay_dead_letter_unconfirmed_retry_same_command")
	}
	fmt.Fprintln(os.Stdout, string(out))
	return 0
}

// replayRefusal names a definite refusal: nothing changed.
func replayRefusal(err error) (string, bool) {
	var refusal *controlplane.ReplayRefusal
	switch {
	case errors.As(err, &refusal):
		return refusal.Reason, true
	case errors.Is(err, controlplane.ErrExpired):
		return "expired", true
	case errors.Is(err, controlplane.ErrUnavailable):
		return "agent_unavailable", true
	case errors.Is(err, controlplane.ErrQueueFull):
		return "queue_full", true
	case errors.Is(err, controlplane.ErrTransition):
		return "not_a_dead_letter", true
	}
	return definiteRefusal(err)
}
