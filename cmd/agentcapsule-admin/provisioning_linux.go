//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

// abandonProvisioning removes a reservation that never obtained any physical
// resource. See controlplane.Store.AbandonProvisioning for the exact limits.
// -confirm repeats the agent ID.
func abandonProvisioning(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("abandon-provisioning", flag.ContinueOnError)
	agent := f.String("agent-id", "", "agent stuck in PROVISIONING")
	g := newGuard(f, "the agent ID")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *agent == "" {
		return fail("configuration_required")
	}
	if !g.allows(*agent) {
		return fail("confirmation_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	out, err := s.AbandonProvisioning(ctx, g.command(), *agent)
	if err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("abandon_provisioning_rejected_" + reason)
		}
		return fail("abandon_provisioning_unconfirmed_retry_same_command")
	}
	return report(out)
}
