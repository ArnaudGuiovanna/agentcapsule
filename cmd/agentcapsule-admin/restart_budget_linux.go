//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

// clearAgentFailure lets a FAILED agent boot again, with a new restart
// budget (ADR 012). Its organization can do the same by waking it.
func clearAgentFailure(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("clear-agent-failure", flag.ContinueOnError)
	agent := f.String("agent-id", "", "agent that spent its restart budget")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *agent == "" {
		return fail("configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	cleared, err := s.ClearAgentFailure(ctx, *agent)
	if err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("clear_agent_failure_rejected_" + reason)
		}
		return fail("clear_agent_failure_unconfirmed_retry_same_command")
	}
	if !cleared {
		fmt.Fprintln(os.Stdout, "agent_not_failed")
		return 0
	}
	fmt.Fprintln(os.Stdout, "agent_failure_cleared")
	return 0
}
