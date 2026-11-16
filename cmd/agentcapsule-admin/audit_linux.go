//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

// setAuditRetention sets how long audit events are kept (TEN-06): from 30 to
// 36500 days, after which the worker deletes them; -keep-all keeps every
// event, the default (ADR 014). Shortening the retention deletes events for
// good, so -confirm repeats the number of days. -dry-run prints how many
// events the retention would delete now.
func setAuditRetention(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("set-audit-retention", flag.ContinueOnError)
	days := f.Int("days", 0, "keep audit events this many days (30 to 36500)")
	keepAll := f.Bool("keep-all", false, "keep every audit event (the default)")
	g := newGuard(f, "the number of days")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *keepAll == (*days != 0) {
		return fail("configuration_required")
	}
	var retention *int
	if !*keepAll {
		retention = days
		if !g.allows(strconv.Itoa(*days)) {
			return fail("confirmation_required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	out, err := s.SetAuditRetention(ctx, g.command(), retention)
	if err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("audit_retention_rejected_" + reason)
		}
		return fail("audit_retention_unconfirmed_retry_same_command")
	}
	return report(out)
}

// listOperatorAudit prints the operator's audit, one JSON object per line:
// the destructive commands with their outcome, and the audit purges.
func listOperatorAudit(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("list-operator-audit", flag.ContinueOnError)
	after := f.String("after", "", "print the events after this event ID")
	limit := f.Int("limit", 100, "at most this many events (1 to 1000)")
	if err := f.Parse(args); err != nil || f.NArg() != 0 {
		return fail("configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	events, err := s.ListOperatorAudit(ctx, *after, *limit)
	if err != nil {
		return fail("operator_audit_listing_failed")
	}
	enc := json.NewEncoder(os.Stdout)
	for _, e := range events {
		if err = enc.Encode(e); err != nil {
			return fail("operator_audit_output_failed")
		}
	}
	return 0
}
