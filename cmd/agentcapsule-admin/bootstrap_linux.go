//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// operator names the local account that runs a trusted command, in the audit
// of what the command changes. It is not an authentication: whoever reaches
// the database with these rights is trusted (docs/bootstrap.md).
func operator(ctx context.Context) context.Context {
	return controlplane.WithOperator(ctx, operatorName())
}

func operatorName() string { return fmt.Sprintf("local-uid:%d", os.Geteuid()) }

// migrate applies the migrations this binary carries. It is idempotent: a
// database already at this version is only checked.
func migrate(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("migrate", flag.ContinueOnError)
	if err := f.Parse(args); err != nil || f.NArg() != 0 {
		return fail("configuration_required")
	}
	// Large concurrent index builds can outlast connection startup. The
	// operator can interrupt the migration; its next run resumes the ledger.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	startup, stop := context.WithTimeout(ctx, time.Minute)
	s, code := openOperatorStore(startup, fail)
	stop()
	if s == nil {
		return code
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		return fail("database_migration_failed")
	}
	fmt.Fprintln(os.Stdout, "migration_complete")
	return 0
}

// listAudit prints the latest operator actions, newest first, one JSON object
// per line: the platform credential, organizations and their identity trusts.
// It prints no secret, key or token.
func listAudit(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("list-audit", flag.ContinueOnError)
	limit := f.Int("limit", 100, "number of events, 1 to 1000")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *limit < 1 || *limit > 1000 {
		return fail("configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	events, err := s.ListOperatorAudit(ctx, *limit)
	if err != nil {
		return fail("audit_listing_failed")
	}
	enc := json.NewEncoder(os.Stdout)
	for _, e := range events {
		if err = enc.Encode(e); err != nil {
			return fail("audit_output_failed")
		}
	}
	return 0
}
