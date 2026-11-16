//go:build linux && cgo

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// replay-dead-letter needs the dead letter, a key and a whole number of
// seconds, and names each definite refusal (ADR 017). The replay itself is
// tested against PostgreSQL in internal/controlplane.
func TestReplayDeadLetterCommand(t *testing.T) {
	t.Setenv("AGENTCAPSULE_DATABASE_URL", "")
	for _, args := range [][]string{
		{"replay-dead-letter"},
		{"replay-dead-letter", "-operation-id", "op_1"},
		{"replay-dead-letter", "-key", "k"},
		{"replay-dead-letter", "-operation-id", "op_1", "-key", "k", "-ttl", "1500ms"},
		{"replay-dead-letter", "-operation-id", "op_1", "-key", "k", "extra"},
	} {
		if out, code := command(t, args...); code != 1 || strings.TrimSpace(out) != "configuration_required" {
			t.Fatal(args, out, code)
		}
	}
	if out, code := command(t, "replay-dead-letter", "-operation-id", "op_1", "-key", "k", "-ttl", "10m"); code != 1 || strings.TrimSpace(out) != "database_configuration_required" {
		t.Fatal(out, code)
	}
	for err, want := range map[error]string{
		&controlplane.ReplayRefusal{Reason: controlplane.ReplayOutcomeUnknown}: "outcome_unknown",
		&controlplane.ReplayRefusal{Reason: controlplane.SkipRequesterRevoked}: "requester_revoked",
		controlplane.ErrExpired:     "expired",
		controlplane.ErrUnavailable: "agent_unavailable",
		controlplane.ErrQueueFull:   "queue_full",
		controlplane.ErrTransition:  "not_a_dead_letter",
		controlplane.ErrNotFound:    "not_found",
	} {
		if got, definite := replayRefusal(err); !definite || got != want {
			t.Fatal(err, got, definite)
		}
	}
	if _, definite := replayRefusal(errors.New("connection reset")); definite {
		t.Fatal("an unknown error is a definite refusal")
	}
}
