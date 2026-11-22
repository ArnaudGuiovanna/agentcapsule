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

func openOperatorStore(ctx context.Context, fail func(string) int) (*controlplane.Store, int) {
	dsn, code := databaseURL()
	if code != "" {
		return nil, fail(code)
	}
	s, err := controlplane.OpenWith(ctx, dsn, controlplane.AdminConnections)
	if err != nil {
		return nil, fail("database_initialization_failed")
	}
	return s, 0
}

// listCredentials prints one JSON object per platform or service credential.
// It never prints a hash or a secret.
func listCredentials(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("list-credentials", flag.ContinueOnError)
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
	list, err := s.ListOperatorCredentials(ctx)
	if err != nil {
		return fail("credential_listing_failed")
	}
	enc := json.NewEncoder(os.Stdout)
	for _, c := range list {
		if err = enc.Encode(c); err != nil {
			return fail("credential_output_failed")
		}
	}
	return 0
}

// revokeCredential permanently revokes one platform or service credential. To
// rotate, revoke the old credential, then run bootstrap or bootstrap-platform
// with a NEW token file: existing files are never overwritten and a revoked
// secret is never accepted again. -confirm repeats the credential ID.
func revokeCredential(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("revoke-credential", flag.ContinueOnError)
	kind := f.String("kind", "", "platform or service")
	id := f.String("id", "", "credential ID from list-credentials")
	g := newGuard(f, "the credential ID")
	access := newAccessFlags(f)
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *kind == "" || *id == "" {
		return fail("configuration_required")
	}
	if !g.allows(*id) {
		return fail("confirmation_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	// The revocation appends its record to the authority service before it
	// commits (ADR 006 wave 5); a dry run records nothing.
	if !*g.dryRun {
		authorities, code := access.attach(ctx, s)
		if code != "" {
			return fail(code)
		}
		if authorities != nil {
			defer authorities.Close()
		}
	}
	out, err := s.RevokeOperatorCredential(operator(ctx), g.command(), *kind, *id)
	if err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("credential_revocation_rejected_" + reason)
		}
		if errors.Is(err, controlplane.ErrAuthorityUnavailable) {
			return fail("authority_unavailable_try_again")
		}
		return fail("credential_revocation_unconfirmed_retry_same_command")
	}
	return report(out)
}
